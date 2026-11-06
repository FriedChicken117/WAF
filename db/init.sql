-- Base de datos de laboratorio para el WAF. Ejecutar en SQL Server (SSMS, Azure Data Studio o sqlcmd).
-- Cambia la contraseña de waf_app (y la de appsettings.json / variable de entorno) antes de usarlo.

IF DB_ID(N'TiendaWaf') IS NULL CREATE DATABASE TiendaWaf;
GO
USE TiendaWaf;
GO

IF OBJECT_ID(N'dbo.Productos') IS NULL
    CREATE TABLE dbo.Productos (
        Id     INT IDENTITY(1,1) PRIMARY KEY,
        Nombre NVARCHAR(100)  NOT NULL,
        Precio DECIMAL(10,2)  NOT NULL
    );

IF OBJECT_ID(N'dbo.Usuarios') IS NULL
    CREATE TABLE dbo.Usuarios (
        Id            INT IDENTITY(1,1) PRIMARY KEY,
        NombreUsuario NVARCHAR(50)  NOT NULL,
        Clave         NVARCHAR(100) NOT NULL   -- datos ficticios de demostración
    );
GO

IF NOT EXISTS (SELECT 1 FROM dbo.Productos)
    INSERT INTO dbo.Productos (Nombre, Precio) VALUES
        (N'Zapatos rojos',      120000),
        (N'Zapatos negros',     135000),
        (N'Camisa de algodón',   65000),
        (N'Pantalón de lino',    89000),
        (N'Chaqueta impermeable', 210000),
        (N'Gorra deportiva',     35000),
        (N'Medias x3',           18000),
        (N'Correa de cuero',     47000);

IF NOT EXISTS (SELECT 1 FROM dbo.Usuarios)
    INSERT INTO dbo.Usuarios (NombreUsuario, Clave) VALUES
        (N'admin',   N'clave_demo_no_real'),
        (N'cliente', N'otra_clave_demo');
GO

-- Usuario de la aplicación con MÍNIMO privilegio: solo puede leer Productos.
-- Así, aunque una inyección SQL lograra pasar, no podría leer Usuarios ni modificar nada.
IF SUSER_ID(N'waf_app') IS NULL
    CREATE LOGIN waf_app WITH PASSWORD = N'CambiarEstaClave_123!', CHECK_POLICY = ON;
GO
IF USER_ID(N'waf_app') IS NULL
    CREATE USER waf_app FOR LOGIN waf_app;
GO
GRANT SELECT ON dbo.Productos TO waf_app;
-- Opcional, solo para ver una fuga de datos con UNION SELECT en el laboratorio:
-- GRANT SELECT ON dbo.Usuarios TO waf_app;
GO
