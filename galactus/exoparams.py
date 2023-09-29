def reward_user(ga):
    return ga

admin_key = 'deez-nuts'
unit_test_mode = True
pg_path = "postgresql://galactus:deez_nuts@localhost:5432/galactus"
sqlite_main_path = "sqlite+pysqlite:///main.db"
sqlite_logs_path = "sqlite+pysqlite:///logs.db"
sqlite_mem_path = "sqlite+pysqlite:///:memory:"
drop_on_start = "True"
test_db = "postgres"
#test_db = "sqlite-mem"
#test_db = "sqlite-file"
test_log_db = "postgres"
#test_log_db = "sqlite-mem"
#test_log_db = "sqlite-file"

