use super::*;

fn environment(without: &str, empty: &str) -> impl Fn(&str) -> Option<String> {
    move |name| match name {
        name if name == without => None,
        name if name == empty => Some(String::new()),
        name => Some(format!("value of {name}")),
    }
}

#[test]
fn reads_each_setting_from_its_variable() {
    assert_eq!(
        Settings::read(environment("", "")).unwrap(),
        Settings {
            table: "value of MAIL_BUDGET_TABLE".into(),
            budget_key_secret: "value of MAIL_BUDGET_KEY_SECRET".into(),
            email_key: "value of COGNITO_EMAIL_KEY_ARN".into(),
        }
    );
}

/// No secret named is no sender, so nothing can be sent.
#[test]
fn an_unset_or_empty_variable_is_refused_by_name() {
    for name in [TABLE_VARIABLE, SECRET_VARIABLE, KEY_VARIABLE] {
        for variables in [environment(name, ""), environment("", name)] {
            assert!(matches!(
                Settings::read(variables),
                Err(MailError::Configuration(missing)) if missing == name
            ));
        }
    }
}
