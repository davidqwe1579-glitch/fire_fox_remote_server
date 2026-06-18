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

struct ConnectionInfo {
    id: u64,
    uuid: String,
    session_id: String,
    disconnect_tx: tokio::sync::oneshot::Sender<()>,
}

#[derive(Clone)]
struct AppState {
    db: MySqlPool,
    active_connections: Arc<Mutex<HashMap<String, Vec<ConnectionInfo>>>>,
}

static NEXT_CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Deserialize)]
struct AuthRequest {
    user_id: String,
    uuid: Option<String>,
    session_id: Option<String>,
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
        .max_connections(50)
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
    let conn_id = NEXT_CONN_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Some(msg) = socket.recv().await {
        if let Ok(Message::Text(text)) = msg {
            if let Ok(req) = serde_json::from_str::<AuthRequest>(&text) {
                let user_id = req.user_id.clone();
                
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

                        let client_uuid = req.uuid.clone().unwrap_or_default();
                        let client_session_id = req.session_id.clone().unwrap_or_default();
                        let mut conns = state.active_connections.lock().await;
                        let conns_list = conns.entry(user_id.clone()).or_insert_with(Vec::new);
                        
                        // Always evict duplicate session_id first (reconnections of the same running process)
                        let mut evicted = false;
                        if !client_session_id.is_empty() {
                            if let Some(pos) = conns_list.iter().position(|c| c.session_id == client_session_id) {
                                let old_conn = conns_list.remove(pos);
                                let _ = old_conn.disconnect_tx.send(());
                                evicted = true;
                            }
                        }
                        // Fallback to uuid eviction if session_id was not provided
                        if !evicted && client_session_id.is_empty() && !client_uuid.is_empty() {
                            if let Some(pos) = conns_list.iter().position(|c| c.uuid == client_uuid) {
                                let old_conn = conns_list.remove(pos);
                                let _ = old_conn.disconnect_tx.send(());
                            }
                        }

                        // If limit is exceeded, reject this new connection with LIMIT_EXCEEDED.
                        if conns_list.len() >= max_connections as usize {
                            drop(conns);
                            let resp = AuthResponse {
                                status: "ERROR".to_string(),
                                message: "LIMIT_EXCEEDED".to_string(),
                            };
                            let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            let _ = socket.close().await;
                            return;
                        }

                        // Create disconnect channel for this connection
                        let (disconnect_tx, mut disconnect_rx) = tokio::sync::oneshot::channel::<()>();
                        conns_list.push(ConnectionInfo {
                            id: conn_id,
                            uuid: client_uuid,
                            session_id: client_session_id,
                            disconnect_tx,
                        });
                        let current_count = conns_list.len() as i32;
                        let db_count = current_count - 1;
                        drop(conns);

                        // Update DB with the current active connection count
                        let _ = sqlx::query("UPDATE user SET current_connections = ? WHERE user_id = ?")
                            .bind(db_count)
                            .bind(&user_id)
                            .execute(&state.db)
                            .await;
                        
                        let resp = AuthResponse {
                            status: "OK".to_string(),
                            message: "LOGGED_IN".to_string(),
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;

                        let (mut sender, mut receiver) = socket.split();
                        let user_id_clone = user_id.clone();
                        let state_clone = state.clone();
                        let mut check_interval = tokio::time::interval(Duration::from_secs(10));
                        
                        tokio::select! {
                            _ = &mut disconnect_rx => {
                                let resp = AuthResponse {
                                    status: "ERROR".to_string(),
                                    message: "EVICTED".to_string(),
                                };
                                let _ = sender.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            }
                            _ = async {
                                loop {
                                    check_interval.tick().await;
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
                                        Err(e) => {
                                            eprintln!("Database error in expiration check for user {}: {:?}", user_id_clone, e);
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
                            } => {}
                        }

                        // Decrement connection list / clean up this connection on disconnect
                        let mut conns = state.active_connections.lock().await;
                        let mut current_count = 0;
                        if let Some(conns_list) = conns.get_mut(&user_id) {
                            conns_list.retain(|c| c.id != conn_id);
                            current_count = conns_list.len() as i32;
                            if conns_list.is_empty() {
                                conns.remove(&user_id);
                            }
                        }
                        let db_count = current_count - 1;
                        drop(conns);

                        // Update DB with the new count
                        let _ = sqlx::query("UPDATE user SET current_connections = ? WHERE user_id = ?")
                            .bind(db_count)
                            .bind(&user_id)
                            .execute(&state.db)
                            .await;
                    }
                    Err(_) => {
                        let resp = AuthResponse {
                            status: "ERROR".to_string(),
                            message: "INVALID_USER".to_string(),
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                        let _ = socket.close().await;
                    }
                }
            }
        }
    }
}
