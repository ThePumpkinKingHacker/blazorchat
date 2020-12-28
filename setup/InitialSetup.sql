IF NOT EXISTS (select * from sysobjects where name='Users' and xtype='U')
	CREATE TABLE [Users] (
		[ID] int NOT NULL IDENTITY,
		[UserName] varchar(50) NOT NULL,
		[Password] binary(32) NOT NULL,
		[Salt] binary(16) NOT NULL,
		[RoleEnum] tinyint NOT NULL, --0=Admin,1=User
		CONSTRAINT User_PK PRIMARY KEY (ID)	
	)
GO

IF NOT EXISTS (select * from sysobjects where name='Messages' and xtype='U')
	CREATE TABLE [Messages] (
		[ID] int NOT NULL IDENTITY,
		[UserID] int NOT NULL,
		[Timestamp] datetime NOT NULL,
		[Content] varchar(1000) NOT NULL,
		CONSTRAINT Message_PK PRIMARY KEY (ID),
		CONSTRAINT Message_FK1 FOREIGN KEY (UserID) REFERENCES [Users]
	);
GO
