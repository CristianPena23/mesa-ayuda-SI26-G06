-- Migracion de la Parte 6 - Grupo SI26-G06
-- Se ejecuta UNA vez como administrador de MySQL en sg-robayo-db:
--   sudo mysql < migracion-parte6.sql
USE mesa_ayuda;

-- 1) El hash nuevo (scrypt con sal) mide ~100 caracteres; el campo era de 64.
ALTER TABLE usuarios MODIFY password_hash VARCHAR(255) NOT NULL;

-- 2) Los hashes MD5 viejos ya no se aceptan (MD5 sin sal no es seguro y no se
--    puede convertir: no se puede "deshacer" un hash). Se bloquean esas cuentas
--    marcando el hash como invalido; el usuario debe volver a registrarse o el
--    administrador le asigna una clave nueva. '!' nunca coincide con scrypt.
UPDATE usuarios SET password_hash = '!' WHERE password_hash NOT LIKE 'scrypt$%';
