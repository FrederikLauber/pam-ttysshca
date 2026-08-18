use axum::{
    extract::{Form, State},
    response::Html,
    routing::post,
    Router,
};
#[cfg(test)]
use axum::body::{to_bytes, Body};
#[cfg(test)]
use axum::http::{Request, StatusCode};
use std::env;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use tower::util::ServiceExt;
use tokio::net::TcpListener;
#[cfg(test)]
use shared::{load_certificate, load_private_key};
use shared::{Answer, AnswerEngine, Certificate, Challenge, PrivateKey, PrivateKeyAndCertificate};

#[derive(serde::Deserialize)]
struct ValueForm {
    value: String,
}

const HTML_TEMPLATE: &str = include_str!("../../template/index.html");

#[tokio::main]
async fn main() {
    let port = env::var("FUNCTIONS_CUSTOMHANDLER_PORT")
        .unwrap_or_else(|_| "8080".to_string());

    let engine = Arc::new(build_engine_from_env());
    let app = build_app(engine);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();

    axum::serve(listener, app)
        .await
        .unwrap();
}

fn build_engine_from_env() -> PrivateKeyAndCertificate {

    let private_key_str = std::env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY not configured");

    let certificate_str = std::env::var("CERTIFICATE")
        .expect("CERTIFICATE not configured");

    let private_key = PrivateKey::from_str(&private_key_str).expect("PRIVATE_KEY is not valid private key");
    let certificate = Certificate::from_str(&certificate_str).expect("CERTIFICATE is not valid certificate");

    PrivateKeyAndCertificate::new(private_key, certificate).expect("Could not create answer engine")
}

fn build_app(engine: Arc<PrivateKeyAndCertificate>) -> Router {
    Router::new()
        .route("/api/", post(value))
        .route("/api/", axum::routing::get(index))
        .with_state(engine)
}

async fn index() -> Html<String> {
    render("")
}

async fn value(State(engine): State<Arc<PrivateKeyAndCertificate>>,
               Form(form): Form<ValueForm>) -> Html<String> {

    let answer = match Challenge::try_from(&form.value) {
        Ok(challenge) => {
            engine.generate_answer(&challenge)
        },
        Err(e) => {
            let output = format!("No challenge found in input: {e}");
            return render(&output);
        }
    };

    render_answer(answer)
}

fn render_answer(answer: Result<Answer, String>) -> Html<String> {
    match answer {
        Ok(answer) => render(&answer.to_string()),
        Err(e) => render(&e),
    }
}

fn render(output: &str) -> Html<String> {
    let html = HTML_TEMPLATE
        .replace("{{OUTPUT}}", html_escape(output).as_str());

    Html(html)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
fn build_test_engine() -> Arc<PrivateKeyAndCertificate> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let private_key = load_private_key(&root.join("../../tests/signed"), None::<&[u8]>)
        .expect("failed to load test private key");
    let certificate = load_certificate(&root.join("../../tests/signed-cert.pub"))
        .expect("failed to load test certificate");

    Arc::new(
        PrivateKeyAndCertificate::new(private_key, certificate)
            .expect("failed to build test answer engine"),
    )
}

#[cfg(test)]
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded::to_string;

    fn with_private_env<T>(private_key: String, certificate: String, action: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_private = env::var("PRIVATE_KEY").ok();
        let old_certificate = env::var("CERTIFICATE").ok();

        // Guarded by ENV_LOCK so test threads do not concurrently mutate process env.
        unsafe {
            env::set_var("PRIVATE_KEY", private_key);
            env::set_var("CERTIFICATE", certificate);
        }

        let result = action();

        // Restore previous process env values for test isolation.
        unsafe {
            if let Some(value) = old_private {
                env::set_var("PRIVATE_KEY", value);
            } else {
                env::remove_var("PRIVATE_KEY");
            }

            if let Some(value) = old_certificate {
                env::set_var("CERTIFICATE", value);
            } else {
                env::remove_var("CERTIFICATE");
            }
        }

        result
    }

    #[tokio::test]
    async fn get_api_returns_html() {
        let app = build_app(build_test_engine());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<form method=\"post\" action=\"/api/\">"));
    }

    #[tokio::test]
    async fn post_api_with_valid_challenge_returns_answer() {
        let app = build_app(build_test_engine());
        let challenge = Challenge::new().to_string();
        let form = to_string([("value", challenge)]).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("No challenge found in input:"));
        assert!(html.contains("[[["));
    }

    #[tokio::test]
    async fn post_api_with_invalid_challenge_returns_error_message() {
        let app = build_app(build_test_engine());
        let form = to_string([("value", "this-is-not-a-challenge")]).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("No challenge found in input:"));
    }

    #[test]
    fn render_answer_error_branch_renders_text() {
        let Html(html) = render_answer(Err("could not sign".to_string()));
        assert!(html.contains("could not sign"));
    }

    #[test]
    fn build_engine_from_env_works_with_test_material() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let private_key = fs::read_to_string(root.join("../../tests/signed")).unwrap();
        let certificate = fs::read_to_string(root.join("../../tests/signed-cert.pub")).unwrap();

        let engine = with_private_env(private_key, certificate, build_engine_from_env);
        let answer = engine.generate_answer(&Challenge::new());
        assert!(answer.is_ok());
    }
}

