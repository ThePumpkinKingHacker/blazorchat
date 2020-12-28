#!/bin/bash

# Wait to be sure that SQL Server came up
echo "Waiting for SQL to come online..."
sleep 90s

# Run the setup script to create the DB and the schema in the DB
# Note: make sure that your password matches what is in the Dockerfile
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P "$SA_PASSWORD" -d master -i /usr/share/sql/InitialSetup.sql
echo "Created initial database -- If no error happened, we're good!"
