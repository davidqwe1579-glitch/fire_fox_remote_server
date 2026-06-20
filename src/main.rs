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
    is_manager: bool,
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
    is_manager: Option<bool>,
}

#[derive(Serialize)]
struct AuthResponse {
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expire_date: Option<String>,
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

    // Reset current_connections to -1 and manager_logged_in to 0 on startup
    let _ = sqlx::query("UPDATE user SET current_connections = -1, manager_logged_in = 0")
        .execute(&pool)
        .await;

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
                let row: Result<(chrono::NaiveDateTime, i32, i8), sqlx::Error> = sqlx::query_as(
                    "SELECT expire_date, connections, manager_logged_in FROM user WHERE user_id = ?"
                )
                .bind(&user_id)
                .fetch_one(&state.db)
                .await;

                match row {
                    Ok((expire_date, max_connections, manager_logged_in)) => {
                        let now = chrono::Utc::now().naive_utc();
                        if now > expire_date {
                            let resp = AuthResponse {
                                status: "ERROR".to_string(),
                                message: "EXPIRED".to_string(),
                                expire_date: None,
                            };
                            let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            let _ = socket.close().await;
                            return;
                        }

                        let client_uuid = req.uuid.clone().unwrap_or_default();
                        let client_session_id = req.session_id.clone().unwrap_or_default();
                        let client_is_manager = req.is_manager.unwrap_or(false);
                        
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

                        // Check if trying to log in as manager
                        if client_is_manager {
                            let mut has_manager = conns_list.iter().any(|c| c.is_manager);
                            if !has_manager && manager_logged_in != 0 {
                                // If DB says manager logged in, but no active manager in memory, trust memory and heal DB
                                has_manager = false;
                            }

                            if has_manager {
                                drop(conns);
                                let resp = AuthResponse {
                                    status: "ERROR".to_string(),
                                    message: "MANAGER_ALREADY_LOGGED_IN".to_string(),
                                    expire_date: None,
                                };
                                let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                                let _ = socket.close().await;
                                return;
                            }
                        }

                        // If limit is exceeded, reject this new connection with LIMIT_EXCEEDED.
                        if conns_list.len() >= max_connections as usize {
                            drop(conns);
                            let resp = AuthResponse {
                                status: "ERROR".to_string(),
                                message: "LIMIT_EXCEEDED".to_string(),
                                expire_date: None,
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
                            is_manager: client_is_manager,
                            disconnect_tx,
                        });
                        let current_count = conns_list.len() as i32;
                        let db_count = current_count - 1;
                        drop(conns);

                        // Update DB with the current active connection count and manager status
                        if client_is_manager {
                            let _ = sqlx::query("UPDATE user SET current_connections = ?, manager_logged_in = 1 WHERE user_id = ?")
                                .bind(db_count)
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                        } else {
                            let _ = sqlx::query("UPDATE user SET current_connections = ? WHERE user_id = ?")
                                .bind(db_count)
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                        }
                        
                        let resp = AuthResponse {
                            status: "OK".to_string(),
                            message: "LOGGED_IN".to_string(),
                            expire_date: Some(expire_date.format("%Y-%m-%d %H:%M:%S").to_string()),
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
                                    expire_date: None,
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
                                                    expire_date: None,
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
                        let mut was_manager = false;
                        if let Some(conns_list) = conns.get_mut(&user_id) {
                            if let Some(pos) = conns_list.iter().position(|c| c.id == conn_id) {
                                let conn_info = conns_list.remove(pos);
                                was_manager = conn_info.is_manager;
                            }
                            current_count = conns_list.len() as i32;
                            if conns_list.is_empty() {
                                conns.remove(&user_id);
                            }
                        }
                        let db_count = current_count - 1;
                        drop(conns);

                        // Update DB with the new count and manager status
                        if was_manager {
                            let _ = sqlx::query("UPDATE user SET current_connections = ?, manager_logged_in = 0 WHERE user_id = ?")
                                .bind(db_count)
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                        } else {
                            let _ = sqlx::query("UPDATE user SET current_connections = ? WHERE user_id = ?")
                                .bind(db_count)
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                        }
                    }
                    Err(_) => {
                        let resp = AuthResponse {
                            status: "ERROR".to_string(),
                            message: "INVALID_USER".to_string(),
                            expire_date: None,
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                        let _ = socket.close().await;
                    }
                }
            }
        }
    }
}
