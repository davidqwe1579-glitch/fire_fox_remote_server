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

#[derive(Clone)]
struct AppState {
    db: MySqlPool,
    active_connections: Arc<Mutex<HashMap<String, i32>>>,
}

#[derive(Deserialize)]
struct AuthRequest {
    user_id: String,
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

                        let mut conns = state.active_connections.lock().await;
                        let current_count = conns.get(&user_id).copied().unwrap_or(0);
                        
                        if current_count >= max_connections {
                            let resp = AuthResponse {
                                status: "ERROR".to_string(),
                                message: "LIMIT_EXCEEDED".to_string(),
                            };
                            let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                            let _ = socket.close().await;
                            return;
                        }

                        conns.insert(user_id.clone(), current_count + 1);
                        drop(conns);
                        
                        let resp = AuthResponse {
                            status: "OK".to_string(),
                            message: "LOGGED_IN".to_string(),
                        };
                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;

                        let (mut sender, mut receiver) = socket.split();
                        let user_id_clone = user_id.clone();
                        let state_clone = state.clone();
                        let mut check_interval = tokio::time::interval(Duration::from_secs(5));
                        
                        tokio::select! {
                            _ = async {
                                loop {
                                    check_interval.tick().await;
                                    let row: Result<(chrono::NaiveDateTime,), sqlx::Error> = sqlx::query_as(
                                        "SELECT expire_date FROM user WHERE user_id = ?"
                                    )
                                    .bind(&user_id_clone)
                                    .fetch_one(&state_clone.db)
                                    .await;

                                    if let Ok((expire_date,)) = row {
                                        let now = chrono::Utc::now().naive_utc();
                                        if now > expire_date {
                                            let resp = AuthResponse {
                                                status: "ERROR".to_string(),
                                                message: "EXPIRED".to_string(),
                                            };
                                            let _ = sender.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                                            break;
                                        }
                                    } else {
                                        break; 
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

                        // Decrement connection limit on disconnect
                        let mut conns = state.active_connections.lock().await;
                        if let Some(c) = conns.get_mut(&user_id) {
                            *c -= 1;
                            if *c <= 0 {
                                conns.remove(&user_id);
                            }
                        }
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
