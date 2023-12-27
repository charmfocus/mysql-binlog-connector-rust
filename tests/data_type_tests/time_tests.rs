#[cfg(test)]
mod test {
    use mysql_binlog_connector_rust::column::column_value::ColumnValue;
    use serial_test::serial;

    use crate::runner::test_runner::test::TestRunner;

    #[test]
    #[serial]
    fn test_time6() {
        let col_type = "TIME(6)";

        let values = vec![
            "'00:00:00.000000'",
            "'23:59:59.999999'",
            "'03:04:05.0'",
            "'03:04:05.1'",
            "'03:04:05.12'",
            "'03:04:05.123'",
            "'03:04:05.1234'",
            "'03:04:05.12345'",
            "'03:04:05.123456'",
            "'03:04:05.000001'",
            "'03:04:05.000012'",
            "'03:04:05.000123'",
            "'03:04:05.001234'",
            "'03:04:05.012345'",
        ];

        let check_values = [
            "00:00:00.000000",
            "23:59:59.999999",
            "03:04:05.000000",
            "03:04:05.100000",
            "03:04:05.120000",
            "03:04:05.123000",
            "03:04:05.123400",
            "03:04:05.123450",
            "03:04:05.123456",
            "03:04:05.000001",
            "03:04:05.000012",
            "03:04:05.000123",
            "03:04:05.001234",
            "03:04:05.012345",
        ];

        run_and_check(col_type, &values, &check_values);
    }

    #[test]
    #[serial]
    fn test_time3() {
        let col_type = "TIME(3)";

        let values = vec![
            "'00:00:00.000'",
            "'23:59:59.999'",
            "'03:04:05.0'",
            "'03:04:05.1'",
            "'03:04:05.12'",
            "'03:04:05.123'",
            "'03:04:05.001'",
            "'03:04:05.012'",
        ];

        let check_values = [
            "00:00:00.000000",
            "23:59:59.999000",
            "03:04:05.000000",
            "03:04:05.100000",
            "03:04:05.120000",
            "03:04:05.123000",
            "03:04:05.001000",
            "03:04:05.012000",
        ];

        run_and_check(col_type, &values, &check_values);
    }

    #[test]
    #[serial]
    fn test_time() {
        let col_type = "TIME";
        // the db values are actual: ["00:00:00", "23:59:59"]
        // the parsed binlog values are ["00:00:00.000000", "23:59:59.000000"]
        // we keep the 6 pending zeros since we don't know the field precision when parsing binlog
        let values = vec!["'00:00:00'", "'23:59:59'"];
        let check_values = ["00:00:00.000000", "23:59:59.000000"];
        run_and_check(col_type, &values, &check_values);
    }

    fn run_and_check(col_type: &str, values: &[&str], check_values: &[&str]) {
        let runner =
            TestRunner::run_one_col_test(col_type, values, &vec!["SET @@session.time_zone='UTC'"]);

        assert_eq!(runner.insert_events[0].rows.len(), check_values.len());
        for i in 0..check_values.len() {
            assert_eq!(
                runner.insert_events[0].rows[i].column_values[0],
                ColumnValue::Time(check_values[i].to_string()),
            );
        }
    }
}
