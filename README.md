WEB EASY
--------

  a web archive of easy

# Docker
  `docker compose -p webeasy up -d`
  `docker compose down`

# Kore
  `docker run -it -v ./app:/app -w /app kore/kodev:kodev-arm64 build` 

# PostgreSQL
  `DB_NAME=webeasy envsubst < db/class.sql > db/init.sql`

