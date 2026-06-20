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
    username: String,
    hostname: String,
    platform: String,
    is_manager: bool,
    broadcast_tx: tokio::sync::mpsc::UnboundedSender<Message>,
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
    username: Option<String>,
    hostname: Option<String>,
    platform: Option<String>,
    is_manager: Option<bool>,
}

#[derive(Serialize)]
struct AuthResponse {
    status: String,
    message: String,
    is_manager: bool,
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

    // Initialize connection counters on startup
    let _ = sqlx::query("UPDATE user SET current_connections = 0, manager_logged_in = 0")
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
                    Ok((expire_date, max_connections, mut manager_logged_in)) => {
                        let now = chrono::Utc::now().naive_utc();
                        if now > expire_date {
                            let resp = AuthResponse {
                                status: "ERROR".to_string(),
                                message: "EXPIRED".to_string(),
                                is_manager: false,
                            };
                            let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            let _ = socket.close().await;
                            return;
                        }

                        let client_uuid = req.uuid.clone().unwrap_or_default();
                        let client_session_id = req.session_id.clone().unwrap_or_default();
                        let client_is_manager = req.is_manager.unwrap_or(false);

                        eprintln!("[CONN] Request - User: {}, UUID: '{}', Session: '{}', is_manager: {}", user_id, client_uuid, client_session_id, client_is_manager);

                        let mut conns = state.active_connections.lock().await;
                        let conns_list = conns.entry(user_id.clone()).or_insert_with(Vec::new);

                        eprintln!("[CONN] Before check - Active count: {}. Connections: {:?}",
                            conns_list.len(),
                            conns_list.iter().map(|c| format!("(session_id: '{}', uuid: '{}')", c.session_id, c.uuid)).collect::<Vec<_>>()
                        );

                        // Always evict duplicate session_id first
                        let mut evicted = false;
                        if !client_session_id.is_empty() {
                            if let Some(pos) = conns_list.iter().position(|c| c.session_id == client_session_id) {
                                let old_conn = conns_list.remove(pos);
                                eprintln!("[CONN] Evicting duplicate session_id: '{}'", client_session_id);
                                if old_conn.is_manager {
                                    let _ = sqlx::query("UPDATE user SET manager_logged_in = 0 WHERE user_id = ?")
                                        .bind(&user_id)
                                        .execute(&state.db)
                                        .await;
                                    manager_logged_in = 0;
                                }
                                let _ = old_conn.disconnect_tx.send(());                                evicted = true;
                            }
                        }
                        // Fallback to uuid eviction
                        if !evicted && !client_uuid.is_empty() {
                            if let Some(pos) = conns_list.iter().position(|c| c.uuid == client_uuid) {
                                let old_conn = conns_list.remove(pos);
                                eprintln!("[CONN] Evicting duplicate UUID: '{}'", client_uuid);
                                if old_conn.is_manager {
                                    let _ = sqlx::query("UPDATE user SET manager_logged_in = 0 WHERE user_id = ?")
                                        .bind(&user_id)
                                        .execute(&state.db)
                                        .await;
                                    manager_logged_in = 0;
                                }
                                let _ = old_conn.disconnect_tx.send(());
                                evicted = true;
                            }
                        }

                        // Block duplicate manager logins
                        if client_is_manager {
                            let mgr_flag: i32 = sqlx::query_scalar("SELECT manager_logged_in FROM user WHERE user_id = ?")
                                .bind(&user_id)
                                .fetch_one(&state.db)
                                .await
                                .unwrap_or(0);
                            let manager_present = conns_list.iter().any(|c| c.is_manager);
                            eprintln!("[DEBUG] Manager check - mgr_flag: {}, manager_present: {}, evicted: {}", mgr_flag, manager_present, evicted);
                            if mgr_flag != 0 && manager_present && !evicted {
                                eprintln!("[CONN] Rejected! Manager already logged in for user: {}", user_id);
                                drop(conns);
                                let resp = AuthResponse {
                                    status: "ERROR".to_string(),
                                    message: "MANAGER_ALREADY_LOGGED_IN".to_string(),
                                    is_manager: false,
                                };
                                let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                                let _ = socket.close().await;
                                return;
                            } else if mgr_flag != 0 && !manager_present {
                                eprintln!("[WARN] Stale manager_logged_in flag for user {} - clearing it.", user_id);
                                let _ = sqlx::query("UPDATE user SET manager_logged_in = 0 WHERE user_id = ?")
                                    .bind(&user_id)
                                    .execute(&state.db)
                                    .await;
                            }
                        }

                        // If limit is exceeded, reject
                        if conns_list.len() >= max_connections as usize {
                            eprintln!("[CONN] Rejected! Limit {} reached.", max_connections);
                            drop(conns);
                            let resp = AuthResponse {
                                status: "ERROR".to_string(),
                                message: "LIMIT_EXCEEDED".to_string(),
                                is_manager: false,
                            };
                            let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            let _ = socket.close().await;
                            return;
                        }

                        eprintln!("[CONN] Accepted!");

                        // Create channels for this connection
                        let (disconnect_tx, disconnect_rx) = tokio::sync::oneshot::channel::<()>();
                        let (broadcast_tx, mut broadcast_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

                        let client_username = req.username.clone().unwrap_or_default();
                        let client_hostname = req.hostname.clone().unwrap_or_default();
                        let client_platform = req.platform.clone().unwrap_or_default();

                        conns_list.push(ConnectionInfo {
                            id: conn_id,
                            uuid: client_uuid,
                            session_id: client_session_id,
                            username: client_username,
                            hostname: client_hostname,
                            platform: client_platform,
                            is_manager: client_is_manager,
                            broadcast_tx,
                            disconnect_tx,
                        });

                        // Count only non‑manager connections for the DB counter
                        let current_count = conns_list.iter().filter(|c| !c.is_manager).count() as i32;
                        let db_count = current_count; // store actual active non‑manager connection count

                        // Broadcast updated peers list to all clients of this user
                        let peers_payload = serde_json::json!({
                            "status": "PEERS_UPDATE",
                            "peers": conns_list.iter().map(|c| serde_json::json!({
                                "id": c.uuid.clone(),
                                "username": c.username.clone(),
                                "hostname": c.hostname.clone(),
                                "platform": c.platform.clone(),
                            })).collect::<Vec<_>>()
                        }).to_string();
                        for c in conns_list.iter() {
                            let _ = c.broadcast_tx.send(Message::Text(peers_payload.clone().into()));
                        }

                        drop(conns);

                        // Update DB: set manager flag or connection count
                        if client_is_manager {
                            let result = sqlx::query("UPDATE user SET manager_logged_in = 1 WHERE user_id = ?")
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                            match result {
                                Ok(_) => {
                                    let flag: i32 = sqlx::query_scalar(
                                        "SELECT manager_logged_in FROM user WHERE user_id = ?"
                                    )
                                    .bind(&user_id)
                                    .fetch_one(&state.db)
                                    .await
                                    .unwrap_or(0);
                                    eprintln!("[DEBUG] manager_logged_in set to {} for user {}", flag, user_id);
                                }
                                Err(e) => {
                                    eprintln!("[ERROR] Failed to set manager_logged_in: {}", e);
                                }
                            }
                        } else {
                            let _ = sqlx::query("UPDATE user SET current_connections = ? WHERE user_id = ?")
                                .bind(db_count)
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                            eprintln!("[DEBUG] current_connections set to {} for user {}", db_count, user_id);
                        }

                        let resp = AuthResponse {
                            status: "OK".to_string(),
                            message: "LOGGED_IN".to_string(),
                            is_manager: client_is_manager,
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;

                        let (mut sender, mut receiver) = socket.split();
                        let (tx_out, mut rx_out) = tokio::sync::mpsc::unbounded_channel::<Message>();
                        let tx_out_clone1 = tx_out.clone();
                        let tx_out_clone2 = tx_out.clone();
                        let tx_out_clone3 = tx_out.clone();

                        let user_id_clone = user_id.clone();
                        let state_clone = state.clone();
                        let mut check_interval = tokio::time::interval(Duration::from_secs(10));

                        tokio::select! {
                            _ = async {
                                while let Some(msg) = rx_out.recv().await {
                                    let _ = sender.send(msg).await;
                                }
                            } => {}
                            _ = async {
                                while let Some(msg) = broadcast_rx.recv().await {
                                    let _ = tx_out_clone1.send(msg);
                                }
                            } => {}
                            _ = async {
                                if let Ok(_) = disconnect_rx.await {
                                    let resp = AuthResponse {
                                        status: "ERROR".to_string(),
                                        message: "EVICTED".to_string(),
                                        is_manager: false,
                                    };
                                    let _ = tx_out_clone2.send(Message::Text(serde_json::to_string(&resp).unwrap().into()));
                                }
                            } => {}
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
                                                    is_manager: false,
                                                };
                                                let _ = tx_out_clone3.send(Message::Text(serde_json::to_string(&resp).unwrap().into()));
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
                        let mut was_manager = false;
                        let mut db_count: i32 = 0;
                        if let Some(conns_list) = conns.get_mut(&user_id) {
                            if let Some(pos) = conns_list.iter().position(|c| c.id == conn_id) {
                                let conn_info = conns_list.remove(pos);
                                was_manager = conn_info.is_manager;
                            }
                            // Count only non-manager connections remaining
                            db_count = conns_list.iter().filter(|c| !c.is_manager).count() as i32;

                            // Broadcast updated peers list to remaining clients
                            if !conns_list.is_empty() {
                                let peers_payload = serde_json::json!({
                                    "status": "PEERS_UPDATE",
                                    "peers": conns_list.iter().map(|c| serde_json::json!({
                                        "id": c.uuid.clone(),
                                        "username": c.username.clone(),
                                        "hostname": c.hostname.clone(),
                                        "platform": c.platform.clone(),
                                    })).collect::<Vec<_>>()
                                }).to_string();
                                for c in conns_list.iter() {
                                    let _ = c.broadcast_tx.send(Message::Text(peers_payload.clone().into()));
                                }
                            }

                            if conns_list.is_empty() {
                                conns.remove(&user_id);
                            }
                        }
                        drop(conns);

                        // Update DB on disconnect
                        if was_manager {
                            let _ = sqlx::query("UPDATE user SET manager_logged_in = 0 WHERE user_id = ?")
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                            eprintln!("[DEBUG] manager_logged_in reset to 0 for user {}", user_id);
                        } else {
                            let _ = sqlx::query("UPDATE user SET current_connections = ? WHERE user_id = ?")
                                .bind(db_count)
                                .bind(&user_id)
                                .execute(&state.db)
                                .await;
                            eprintln!("[DEBUG] current_connections on disconnect set to {} for user {}", db_count, user_id);
                        }
                    }
                    Err(_) => {
                        let resp = AuthResponse {
                            status: "ERROR".to_string(),
                            message: "INVALID_USER".to_string(),
                            is_manager: false,
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                        let _ = socket.close().await;
                    }
                }
            }
        }
    }
}
