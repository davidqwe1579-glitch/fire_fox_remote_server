use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::sync::oneshot;
use std::sync::atomic::{AtomicU64, Ordering};

struct ActiveSession {
    device_id: String,
    session_id: u64,
    close_tx: oneshot::Sender<()>,
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct AppState {
    db: MySqlPool,
    active_connections: Arc<Mutex<HashMap<String, Vec<ActiveSession>>>>,
}

#[derive(Deserialize)]
struct AuthRequest {
    user_id: String,
    device_id: Option<String>,
}

#[derive(Serialize)]
struct AuthResponse {
    status: String,
    message: String,
}

#[tokio::main]
async fn main() {
    let database_url = "mysql://user_account:Aa102331253910!@localhost/Fire_fox_remote_server";
    let pool = match MySqlPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Failed to connect to database: {}. Please ensure MySQL is running and the database exists.", e);
            return;
        }
    };

    let state = AppState {
        db: pool,
        active_connections: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Auth server listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    if let Some(msg) = socket.recv().await {
        if let Ok(Message::Text(text)) = msg {
            if let Ok(req) = serde_json::from_str::<AuthRequest>(&text) {
                let user_id = req.user_id.clone();
                let device_id = req.device_id.clone().unwrap_or_else(|| "unknown".to_string());
                
                // Use UTC comparison. MySQL DATETIME is retrieved as NaiveDateTime
                let row: Result<(chrono::NaiveDateTime, i32), sqlx::Error> = sqlx::query_as(
                    "SELECT expire_date, connections FROM user WHERE user_id = ?"
                )
                .bind(&user_id)
                .fetch_one(&state.db)
                .await;

                match row {
                    Ok((expire_date, max_connections)) => {
                        let now = chrono::Utc::now().naive_utc();
                        if now > expire_date {
                            let resp = AuthResponse {
                                status: "ERROR".to_string(),
                                message: "EXPIRED".to_string(),
                            };
                            let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            let _ = socket.close().await;
                            return;
                        }

                        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::SeqCst);
                        let (close_tx, mut close_rx) = oneshot::channel::<()>();

                        let mut conns = state.active_connections.lock().await;
                        let sessions = conns.entry(user_id.clone()).or_default();

                        // 1. Evict any existing session with the same device_id (except "unknown")
                        if device_id != "unknown" {
                            if let Some(pos) = sessions.iter().position(|s| s.device_id == device_id) {
                                let old_session = sessions.remove(pos);
                                let _ = old_session.close_tx.send(());
                            }
                        }

                        // 2. Check if we exceed max_connections
                        if sessions.len() as i32 >= max_connections {
                            // Evict the oldest connection
                            let old_session = sessions.remove(0);
                            let _ = old_session.close_tx.send(());
                        }

                        // Add this new session
                        sessions.push(ActiveSession {
                            device_id: device_id.clone(),
                            session_id,
                            close_tx,
                        });
                        drop(conns);

                        let resp = AuthResponse {
                            status: "OK".to_string(),
                            message: "LOGGED_IN".to_string(),
                        };
                        if socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await.is_err() {
                            // Clean up session if sending response fails
                            let mut conns = state.active_connections.lock().await;
                            if let Some(sessions) = conns.get_mut(&user_id) {
                                if let Some(pos) = sessions.iter().position(|s| s.session_id == session_id) {
                                    sessions.remove(pos);
                                }
                                if sessions.is_empty() {
                                    conns.remove(&user_id);
                                }
                            }
                            return;
                        }

                        let (mut sender, mut receiver) = socket.split();
                        let user_id_clone = user_id.clone();
                        let state_clone = state.clone();
                        let mut check_interval = tokio::time::interval(Duration::from_secs(5));
                        
                        tokio::select! {
                            _ = async {
                                loop {
                                    check_interval.tick().await;
                                    
                                    // Send heartbeat to check if socket is still alive
                                    let heartbeat = serde_json::json!({ "status": "PING" });
                                    if sender.send(Message::Text(heartbeat.to_string().into())).await.is_err() {
                                        break;
                                    }

                                    let row: Result<(chrono::NaiveDateTime,), sqlx::Error> = sqlx::query_as(
                                        "SELECT expire_date FROM user WHERE user_id = ?"
                                    )
                                    .bind(&user_id_clone)
                                    .fetch_one(&state_clone.db)
                                    .await;

                                     match row {
                                         Ok((expire_date,)) => {
                                             let now = chrono::Utc::now().naive_utc();
                                             if now > expire_date {
                                                 let resp = AuthResponse {
                                                     status: "ERROR".to_string(),
                                                     message: "EXPIRED".to_string(),
                                                 };
                                                 let _ = sender.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                                                 break;
                                             }
                                         }
                                         Err(sqlx::Error::RowNotFound) => {
                                             let resp = AuthResponse {
                                                 status: "ERROR".to_string(),
                                                 message: "USER_NOT_FOUND".to_string(),
                                             };
                                             let _ = sender.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                                             break;
                                         }
                                         Err(e) => {
                                             eprintln!("Database check query error: {}. Retrying in next tick...", e);
                                         }
                                     }
                                }
                            } => {},
                            _ = async {
                                while let Some(Ok(msg)) = receiver.next().await {
                                    if let Message::Close(_) = msg {
                                        break;
                                    }
                                }
                            } => {},
                            _ = &mut close_rx => {
                                let resp = AuthResponse {
                                    status: "ERROR".to_string(),
                                    message: "LIMIT_EXCEEDED".to_string(),
                                };
                                let _ = sender.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            }
                        }

                        // Decrement connection limit on disconnect
                        let mut conns = state.active_connections.lock().await;
                        if let Some(sessions) = conns.get_mut(&user_id) {
                            if let Some(pos) = sessions.iter().position(|s| s.session_id == session_id) {
                                sessions.remove(pos);
                            }
                            if sessions.is_empty() {
                                conns.remove(&user_id);
                            }
                        }
                    }
                    Err(sqlx::Error::RowNotFound) => {
                        let resp = AuthResponse {
                            status: "ERROR".to_string(),
                            message: "INVALID_USER".to_string(),
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                        let _ = socket.close().await;
                    }
                    Err(e) => {
                        eprintln!("Initial auth database query error: {}", e);
                        let resp = AuthResponse {
                            status: "ERROR".to_string(),
                            message: "SERVER_ERROR".to_string(),
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                        let _ = socket.close().await;
                    }
                }
            }
        }
    }
}
