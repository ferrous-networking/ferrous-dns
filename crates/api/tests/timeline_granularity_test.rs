use ferrous_dns_application::ports::TimeGranularity;

#[test]
fn test_all_variants_exist() {
    let variants = [
        TimeGranularity::Minute,
        TimeGranularity::QuarterHour,
        TimeGranularity::Hour,
        TimeGranularity::Day,
    ];
    assert_eq!(variants.len(), 4);
}
