// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Email8:Store admin UI (RFW) — page definitions served to Sentin8:Dash.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;

use crate::data_api::AppState;

/// `GET /v1/admin/ui/{page}` — RFW definition for the requested page.
#[utoipa::path(
    get,
    path = "/v1/admin/{page}",
    params(("page" = String, Path, description = "RFW page name")),
    responses(
        (status = 200, description = "RFW page definition", body = serde_json::Value),
        (status = 403, description = "Policy deny"),
        (status = 404, description = "Unknown page"),
    ),
    security(),
    tag = "store",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:admin:users",
    )
    .await?;

    let page_def = match page.as_str() {
        "overview" => overview_page(),
        "users" => users_page(),
        "domains" => domains_page(),
        "groups" => groups_page(),
        "quotas" => quotas_page(),
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };

    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(page_def)).unwrap(),
    ))
}

fn overview_page() -> AdminUiPage {
    AdminPage::new("Email Overview")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Mail Platform".into()),
            subtitle: None,
            children: vec![RemoteWidget::Text(WidgetText {
                text: "Principals, domains, groups and quotas for this mail environment.".into(),
                text_type: WidgetTextType::Body,
                align: TextAlign::Left,
                max_lines: None,
            })],
            actions: vec![],
        }))
        .build()
}

fn users_page() -> AdminUiPage {
    AdminPage::new("Mail Users")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Address".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "display_name".into(),
                    label: "Display Name".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "used_bytes".into(),
                    label: "Used".into(),
                    sortable: true,
                    width: None,
                    format: Some("bytes".into()),
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: false,
                    width: None,
                    format: Some("date".into()),
                },
            ],
            data_endpoint: "/users".into(),
            sortable: true,
            filterable: false,
            page_size: 50,
            empty_message: Some("No mail users yet".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn domains_page() -> AdminUiPage {
    AdminPage::new("Mail Domains")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Domain".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "is_enabled".into(),
                    label: "Enabled".into(),
                    sortable: false,
                    width: None,
                    format: Some("bool".into()),
                },
                WidgetDataTableColumn {
                    key: "catch_all".into(),
                    label: "Catch-All".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/domains".into(),
            sortable: true,
            filterable: false,
            page_size: 50,
            empty_message: None,
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn groups_page() -> AdminUiPage {
    AdminPage::new("Mailing Lists")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "address".into(),
                    label: "Address".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "description".into(),
                    label: "Description".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/groups".into(),
            sortable: false,
            filterable: false,
            page_size: 50,
            empty_message: None,
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn quotas_page() -> AdminUiPage {
    AdminPage::new("Quotas")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![WidgetFormField {
                key: "default_account_quota_bytes".into(),
                label: "Default Account Quota (bytes)".into(),
                field_type: FormFieldType::Number,
                required: true,
                placeholder: None,
                default_value: Some(serde_json::Value::Number(serde_json::Number::from(
                    10_737_418_240u64,
                ))),
                options: None,
                validation: Some(FormFieldValidation {
                    min: Some(0.0),
                    max: None,
                    pattern: None,
                    min_length: None,
                    max_length: None,
                    custom_message: Some("Quota must be >= 0 (0 = unlimited)".into()),
                }),
                width: None,
                help_text: Some("0 = unlimited".into()),
                visible_if: None,
            }],
            submit_endpoint: "/quotas".into(),
            submit_label: "Save".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        }))
        .build()
}
