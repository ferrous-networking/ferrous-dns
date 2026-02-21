use ferrous_dns_application::ports::TimeGranularity;

#[test]
fn test_minute_produces_correct_sql_expr() {
    let expr = TimeGranularity::Minute.as_sql_expr();
    assert_eq!(expr, "strftime('%Y-%m-%d %H:%M:00', created_at)");
}

#[test]
fn test_hour_produces_correct_sql_expr() {
    let expr = TimeGranularity::Hour.as_sql_expr();
    assert_eq!(expr, "strftime('%Y-%m-%d %H:00:00', created_at)");
}

#[test]
fn test_day_produces_correct_sql_expr() {
    let expr = TimeGranularity::Day.as_sql_expr();
    assert_eq!(expr, "strftime('%Y-%m-%d 00:00:00', created_at)");
}

#[test]
fn test_quarter_hour_produces_correct_sql_expr() {
    let expr = TimeGranularity::QuarterHour.as_sql_expr();
    assert!(expr.contains("/ 15) * 15"));
}

#[test]
fn test_all_variants_return_static_str() {
    let variants = [
        TimeGranularity::Minute,
        TimeGranularity::QuarterHour,
        TimeGranularity::Hour,
        TimeGranularity::Day,
    ];
    for v in variants {
        let expr = v.as_sql_expr();
        assert!(!expr.is_empty());
        assert!(expr.contains("created_at"));
    }
}
