-- Esquema de la base mesa_ayuda — Grupo SI26-G06
-- Se ejecuta UNA vez en sg-robayo-db como root local:   sudo mysql < schema.sql
--
-- Por qué existe este archivo: la aplicación original crea las tablas al arrancar (init_db),
-- lo que obliga a darle privilegios CREATE/REFERENCES al usuario de la app.
-- Con mínimo privilegio (solo SELECT, INSERT, UPDATE, DELETE) la app ya no puede hacer DDL,
-- así que el esquema lo crea el administrador por separado (separación de funciones).
-- Las tablas son idénticas a las de app/database.py (init_db) del código base.

CREATE DATABASE IF NOT EXISTS mesa_ayuda
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE mesa_ayuda;

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(120) NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    rol VARCHAR(20) NOT NULL DEFAULT 'usuario',
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    titulo VARCHAR(150) NOT NULL,
    descripcion TEXT NOT NULL,
    prioridad VARCHAR(10) NOT NULL DEFAULT 'media',
    estado VARCHAR(20) NOT NULL DEFAULT 'abierto',
    usuario_id INT,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

-- El usuario de la aplicación NO se crea aquí, para no guardar su contraseña en el repositorio.
-- Se crea a mano (ver guía de la Parte 2):
--   CREATE USER 'app_mesa'@'<ip-tailscale-backend>'
--     IDENTIFIED WITH caching_sha2_password BY '<contraseña>' REQUIRE SSL;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON mesa_ayuda.* TO 'app_mesa'@'<ip-tailscale-backend>';
