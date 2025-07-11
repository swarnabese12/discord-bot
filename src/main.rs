use dotenvy::dotenv;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use open;
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::{task, time};
use warp::Filter;

#[derive(Error, Debug)]
pub enum GmailBotError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("OAuth2 error: {0}")]
    OAuth2Error(#[from] oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),
    
    #[error("Environment variable error: {0}")]
    EnvError(#[from] env::VarError),
    
    #[error("URL parsing error: {0}")]
    UrlError(#[from] oauth2::url::ParseError),
    
    #[error("Gmail API error: {message}")]
    GmailApiError { message: String },
    
    #[error("Discord webhook error: {message}")]
    DiscordError { message: String },
    
    #[error("Authorization error: {message}")]
    AuthError { message: String },
    
    #[error("Configuration error: {message}")]
    ConfigError { message: String },
    
    #[error("Token exchange timeout")]
    TokenTimeout,
    
    #[error("No messages found in Gmail response")]
    NoMessages,
    
    #[error("Invalid message format in Gmail response")]
    InvalidMessageFormat,
    
    #[error("Browser open failed: {0}")]
    BrowserError(String),
}

type Result<T> = std::result::Result<T, GmailBotError>;

async fn fetch_and_post_new_emails(
    access_token: &str,
    last_seen_id: &mut Option<String>,
    discord_webhook_url: &str,
) -> Result<()> {
    let important_keywords = [
        "github", "gitlab", "invoice", "payment", "receipt", "account", "login",
        "reset", "verification", "verify", "confirm email", "confirm your email",
        "expired", "expiration", "reminder", "urgent", "suspicious activity",
        "authenticator", "deadline", "follow up", "last chance", "final notice",
        "immediate action", "payment method", "failed payment", "balance due",
        "exceeded", "confirmation token", "access granted"
    ];

    let client = Client::new();

    let list_resp = client
        .get("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1&labelIds=INBOX")
        .bearer_auth(access_token)
        .send()
        .await?;

    // Check if the response is successful
    if !list_resp.status().is_success() {
        return Err(GmailBotError::GmailApiError {
            message: format!("Gmail API returned status: {}", list_resp.status()),
        });
    }

    let list_json = list_resp.json::<serde_json::Value>().await?;

    // Check for API errors in the response
    if let Some(error) = list_json.get("error") {
        return Err(GmailBotError::GmailApiError {
            message: format!("Gmail API error: {}", error),
        });
    }

    let fallback = vec![];
    let messages_raw = list_json["messages"].as_array().unwrap_or(&fallback);
    let messages = messages_raw
        .iter()
        .filter_map(|msg| msg["id"].as_str())
        .collect::<Vec<_>>();

    if let Some(new_id) = messages.first() {
        if Some(new_id.to_string()) != *last_seen_id {
            *last_seen_id = Some(new_id.to_string());

            let msg_detail_resp = client
                .get(&format!(
                    "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date",
                    new_id
                ))
                .bearer_auth(access_token)
                .send()
                .await?;

            // Check if the message detail response is successful
            if !msg_detail_resp.status().is_success() {
                return Err(GmailBotError::GmailApiError {
                    message: format!("Failed to fetch message details: {}", msg_detail_resp.status()),
                });
            }

            let msg_detail = msg_detail_resp.json::<serde_json::Value>().await?;

            // Check for API errors in the message detail response
            if let Some(error) = msg_detail.get("error") {
                return Err(GmailBotError::GmailApiError {
                    message: format!("Gmail API error fetching message: {}", error),
                });
            }

            let headers = msg_detail["payload"]["headers"]
                .as_array()
                .ok_or(GmailBotError::InvalidMessageFormat)?
                .iter()
                .filter_map(|h| {
                    Some((
                        h["name"].as_str()?.to_string(),
                        h["value"].as_str()?.to_string(),
                    ))
                })
                .collect::<HashMap<_, _>>();

            let from = headers.get("From").unwrap_or(&"".to_string()).to_lowercase();
            let subject = headers.get("Subject").unwrap_or(&"".to_string()).to_lowercase();

            // Check conditions
          //  let is_from_swarna = from.contains("swarna.esigns@gmail.com");
            let contains_keyword = important_keywords.iter().any(|kw| subject.contains(kw));

            if contains_keyword {
                let email_info = json!({
                    "from": from,
                    "subject": subject,
                    "date": headers.get("Date").unwrap_or(&"".to_string()),
                    "snippet": msg_detail["snippet"].as_str().unwrap_or("")
                });

                println!("\n📧 Important Email: {}", email_info["subject"]);
                println!("{:?}", email_info);

                post_to_discord(&email_info, discord_webhook_url).await?;
            }
        }
    }

    Ok(())
}

async fn post_to_discord(email_info: &serde_json::Value, webhook_url: &str) -> Result<()> {
    let payload = json!({
        "username": "📬 Gmail Bot",
        "content": format!(
            "**New Email!**\n📨 **From:** {}\n📌 **Subject:** {}\n📅 **Date:** {}\n✉️ **Snippet:** {}",
            email_info["from"], email_info["subject"], email_info["date"], email_info["snippet"]
        )
    });

    let client = Client::new();
    let response = client.post(webhook_url).json(&payload).send().await?;

    // Check if Discord webhook was successful
    if !response.status().is_success() {
        return Err(GmailBotError::DiscordError {
            message: format!("Discord webhook failed with status: {}", response.status()),
        });
    }

    println!("✅ Successfully posted to Discord");
    Ok(())
}

async fn exchange_code_for_token(
    oauth_client: &BasicClient,
    code: String,
) -> Result<String> {
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| GmailBotError::AuthError {
            message: format!("Token exchange failed: {}", e),
        })?;

    Ok(token.access_token().secret().to_string())
}

fn load_environment_variables() -> Result<(String, String, String, String)> {
    let client_id = env::var("CLIENT_ID")
        .map_err(|_| GmailBotError::ConfigError {
            message: "CLIENT_ID environment variable is required".to_string(),
        })?;
    
    let client_secret = env::var("CLIENT_SECRET")
        .map_err(|_| GmailBotError::ConfigError {
            message: "CLIENT_SECRET environment variable is required".to_string(),
        })?;
    
    let redirect_uri = env::var("REDIRECT_URI")
        .map_err(|_| GmailBotError::ConfigError {
            message: "REDIRECT_URI environment variable is required".to_string(),
        })?;
    
    let discord_webhook_url = env::var("DISCORD_WEBHOOK_URL")
        .map_err(|_| GmailBotError::ConfigError {
            message: "DISCORD_WEBHOOK_URL environment variable is required".to_string(),
        })?;

    Ok((client_id, client_secret, redirect_uri, discord_webhook_url))
}

async fn wait_for_token(
    token_result: Arc<Mutex<Option<String>>>,
    timeout_seconds: u64,
) -> Result<String> {
    let start_time = std::time::Instant::now();
    
    loop {
        {
            let lock = token_result.lock().unwrap();
            if let Some(token) = &*lock {
                return Ok(token.clone());
            }
        }
        
        if start_time.elapsed().as_secs() > timeout_seconds {
            return Err(GmailBotError::TokenTimeout);
        }
        
        time::sleep(time::Duration::from_secs(1)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let (client_id, client_secret, redirect_uri, discord_webhook_url) = load_environment_variables()?;

    let oauth_client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
        Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string())?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.clone())?);

    let (auth_url, _csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("https://www.googleapis.com/auth/gmail.readonly".to_string()))
        .url();

    println!("🔗 Open this URL to authorize:");
    println!("{}", auth_url);

    if let Err(e) = open::that(auth_url.as_str()) {
        eprintln!("⚠️  Couldn't open browser automatically: {}", e);
        println!("Please manually copy and paste the URL above into your browser.");
    }

    let token_result = Arc::new(Mutex::new(None));
    let token_result_clone = Arc::clone(&token_result);
    let oauth_client_clone = oauth_client.clone();

    let route = warp::get()
        .and(warp::path("oauth2"))
        .and(warp::path("gmail-bot"))
        .and(warp::query::<HashMap<String, String>>())
        .map(move |query: HashMap<String, String>| {
            let code = query.get("code").cloned().unwrap_or_default();
            let token_result = Arc::clone(&token_result_clone);
            let oauth_client = oauth_client_clone.clone();

            task::spawn(async move {
                match exchange_code_for_token(&oauth_client, code).await {
                    Ok(token) => {
                        let mut lock = token_result.lock().unwrap();
                        *lock = Some(token);
                        println!("✅ Token exchange successful");
                    }
                    Err(e) => {
                        eprintln!("❌ Token exchange failed: {}", e);
                    }
                }
            });

            warp::reply::html("✅ Gmail bot authorized. You can close this tab.")
        });

    tokio::spawn(async move {
        warp::serve(route).run(([127, 0, 0, 1], 3000)).await;
    });

    println!("🔄 Waiting for authorization...");
    let access_token = wait_for_token(token_result, 300).await?;
    println!("✅ Authorization complete! Starting email monitoring...");

    let mut last_seen_id = None;
    loop {
        match fetch_and_post_new_emails(&access_token, &mut last_seen_id, &discord_webhook_url).await {
            Ok(()) => {
                // Success - continue monitoring
            }
            Err(GmailBotError::HttpError(e)) if e.is_timeout() => {
                eprintln!("⏱️  Request timeout, retrying in 30 seconds...");
            }
            Err(e) => {
                eprintln!("❌ Error checking Gmail: {}", e);
                if matches!(e, GmailBotError::AuthError { .. } | GmailBotError::GmailApiError { .. }) {
                    eprintln!("🔄 Authentication may have expired. Please restart the application.");
                    break;
                }
            }
        }
        time::sleep(time::Duration::from_secs(30)).await;
    }
    
    Ok(())
}