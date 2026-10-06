//! `invisible_captcha` / `impersonates` class-body macros become ordinary
//! filters and methods — the same expand-to-IR posture as `rate_limit`.

use std::collections::HashMap;
use std::path::PathBuf;

use roundhouse::emit::ruby;
use roundhouse::ingest::ingest_app_from_tree;
use roundhouse::ingest::survey;

fn emit_named(
    controller_path_suffix: &str,
    application_controller: &str,
    users_controller: &str,
) -> String {
    let files: HashMap<PathBuf, Vec<u8>> = [
        (
            PathBuf::from("db/schema.rb"),
            b"ActiveRecord::Schema.define do\n  create_table \"users\", force: :cascade do |t|\n    t.string \"email\", null: false\n  end\nend\n".to_vec(),
        ),
        (
            PathBuf::from("config/routes.rb"),
            b"Rails.application.routes.draw do\n  resources :users, only: %i[ create show ]\nend\n".to_vec(),
        ),
        (
            PathBuf::from("app/models/user.rb"),
            b"class User < ApplicationRecord\nend\n".to_vec(),
        ),
        (
            PathBuf::from("app/models/application_record.rb"),
            b"class ApplicationRecord < ActiveRecord::Base\n  self.abstract_class = true\nend\n".to_vec(),
        ),
        (
            PathBuf::from("app/controllers/application_controller.rb"),
            application_controller.as_bytes().to_vec(),
        ),
        (
            PathBuf::from("app/controllers/users_controller.rb"),
            users_controller.as_bytes().to_vec(),
        ),
        (
            PathBuf::from("app/views/users/show.html.erb"),
            b"<p>ok</p>\n".to_vec(),
        ),
    ]
    .into_iter()
    .collect();
    survey::activate();
    let mut app = ingest_app_from_tree(files).expect("ingest");
    let gaps = survey::drain();
    assert!(
        gaps.iter().all(|g| {
            let s = format!("{g:?}");
            !s.contains("invisible_captcha") && !s.contains("impersonates")
        }),
        "macros must not survey: {gaps:?}"
    );
    roundhouse::session::analyze_and_lower(&mut app);
    ruby::emit_spinel(&app)
        .iter()
        .find(|f| f.path.ends_with(controller_path_suffix))
        .unwrap_or_else(|| panic!("missing {controller_path_suffix}"))
        .content
        .clone()
}

#[test]
fn invisible_captcha_becomes_a_before_action_and_spam_gate() {
    let src = emit_named(
        "app/controllers/users_controller.rb",
        "class ApplicationController < ActionController::Base\nend\n",
        "class UsersController < ApplicationController\n  invisible_captcha only: :create\n\n  def create\n    render plain: \"created\"\n  end\n\n  def show\n  end\nend\n",
    );
    assert!(
        src.contains("ActionController::InvisibleCaptcha.spam?"),
        "runtime gate call:\n{src}"
    );
    // `only: :create` — the gate is composed into create, not show.
    assert!(
        src.contains("def create") && src.contains("InvisibleCaptcha.spam?"),
        "gate on create:\n{src}"
    );
}

#[test]
fn impersonates_wraps_current_user_and_adds_impersonate_helpers() {
    let src = emit_named(
        "app/controllers/application_controller.rb",
        "class ApplicationController < ActionController::Base\n  def current_user\n    User.find_by(id: session[:signed_in_user_id])\n  end\n\n  impersonates :user\nend\n",
        "class UsersController < ApplicationController\n  def show\n  end\n  def create\n    head :ok\n  end\nend\n",
    );
    assert!(src.contains("def true_user"), "true_user:\n{src}");
    assert!(src.contains("def impersonate_user"), "impersonate_user:\n{src}");
    assert!(
        src.contains("def stop_impersonating_user"),
        "stop_impersonating_user:\n{src}"
    );
    assert!(
        src.contains("session[:impersonated_user_id]"),
        "pretender session key:\n{src}"
    );
    assert!(
        !src.contains("impersonates"),
        "macro must be consumed:\n{src}"
    );
}
