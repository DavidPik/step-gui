#!/bin/sh
mysql -u root -p < internal/db/migrations/0001_init.sql
mysql -u root -p < internal/db/migrations/0002_default_data.sql
mysql -u root -p < internal/db/migrations/0003_indexes.sql
