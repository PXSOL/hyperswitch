// use actix_web::http::header;

use crate::configs::settings;

/// `true` for the routes a payer's browser returns to after a connector redirect:
/// `/payments/{payment_id}/{merchant_id}/redirect/{response|complete}/{connector}[/{creds_identifier}]`.
///
/// An issuer's ACS sends the 3DS result back with a cross-origin form POST, so the browser sends
/// that bank's domain (or `null`) as `Origin`. Those domains cannot be listed in `origins`, and an
/// unlisted origin is rejected with a 400 before the handler runs, which strands the payer on a
/// blank page. These routes authenticate with the merchant id in the URL, so `Origin` protects
/// nothing here.
fn is_payment_redirect_return(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    matches!(
        segments.as_slice(),
        ["", "payments", _, _, "redirect", "response" | "complete", _]
            | [
                "",
                "payments",
                _,
                _,
                "redirect",
                "response" | "complete",
                _,
                _
            ]
    )
}

pub fn cors(config: settings::CorsSettings) -> actix_cors::Cors {
    let allowed_methods = config.allowed_methods.iter().map(|s| s.as_str());

    let mut cors = actix_cors::Cors::default()
        .allowed_methods(allowed_methods)
        .allow_any_header()
        .expose_any_header()
        .max_age(config.max_age);

    if config.wildcard_origin {
        cors = cors.allow_any_origin()
    } else {
        for origin in &config.origins {
            cors = cors.allowed_origin(origin);
        }
        cors = cors.allowed_origin_fn(|_origin, head| is_payment_redirect_return(head.uri.path()));
        // Only allow this in case if it's not wildcard origins. ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
        cors = cors.supports_credentials();
    }

    cors
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use actix_web::{http::StatusCode, test as actix_test, web, App, HttpResponse};

    use super::*;

    const LISTED_ORIGIN: &str = "https://dashboard.example.com";
    const ACS_ORIGIN: &str = "https://acs.example-bank.com";
    const COMPLETE_PATH: &str = "/payments/pay_1/merchant_1/redirect/complete/fiservemea";
    const RESPONSE_PATH: &str = "/payments/pay_1/merchant_1/redirect/response/fiservemea";
    const OTHER_PATH: &str = "/payments/pay_1/confirm";

    fn restricted_settings() -> settings::CorsSettings {
        settings::CorsSettings {
            origins: HashSet::from([LISTED_ORIGIN.to_owned()]),
            wildcard_origin: false,
            max_age: 30,
            allowed_methods: HashSet::from(["GET".to_owned(), "POST".to_owned()]),
        }
    }

    async fn post_status(path: &str, origin: Option<&str>) -> StatusCode {
        let app = actix_test::init_service(
            App::new()
                .wrap(cors(restricted_settings()))
                .default_service(web::to(HttpResponse::Ok)),
        )
        .await;
        let mut request = actix_test::TestRequest::post().uri(path);
        if let Some(origin) = origin {
            request = request.insert_header(("Origin", origin));
        }
        actix_test::call_service(&app, request.to_request())
            .await
            .status()
    }

    #[test]
    fn matches_only_the_payment_redirect_return_routes() {
        for path in [
            COMPLETE_PATH,
            RESPONSE_PATH,
            "/payments/pay_1/merchant_1/redirect/complete/fiservemea/creds_1",
            "/payments/pay_1/merchant_1/redirect/response/fiservemea/creds_1",
        ] {
            assert!(is_payment_redirect_return(path), "{path}");
        }
        for path in [
            OTHER_PATH,
            "/payments",
            "/payments/pay_1/merchant_1/redirect",
            "/payments/pay_1/merchant_1/redirect/complete",
            "/payments/pay_1/merchant_1/redirect/other/fiservemea",
            "/payments/redirect/pay_1/merchant_1/attempt_1",
            "/accounts/pay_1/merchant_1/redirect/complete/fiservemea",
            "/payments/pay_1/merchant_1/redirect/complete/fiservemea/creds_1/extra",
        ] {
            assert!(!is_payment_redirect_return(path), "{path}");
        }
    }

    #[actix_web::test]
    async fn the_acs_can_post_back_to_the_return_routes() {
        assert_eq!(
            post_status(COMPLETE_PATH, Some(ACS_ORIGIN)).await,
            StatusCode::OK
        );
        assert_eq!(
            post_status(RESPONSE_PATH, Some(ACS_ORIGIN)).await,
            StatusCode::OK
        );
        // A sandboxed or no-referrer ACS page sends the literal `null`.
        assert_eq!(
            post_status(COMPLETE_PATH, Some("null")).await,
            StatusCode::OK
        );
    }

    #[actix_web::test]
    async fn every_other_route_still_rejects_an_unlisted_origin() {
        assert_eq!(
            post_status(OTHER_PATH, Some(ACS_ORIGIN)).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_status(OTHER_PATH, Some(LISTED_ORIGIN)).await,
            StatusCode::OK
        );
        assert_eq!(post_status(OTHER_PATH, None).await, StatusCode::OK);
    }
}
