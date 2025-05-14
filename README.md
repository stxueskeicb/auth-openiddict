# auth-openiddict
In order to setup the original database, run the following under /AuthServer

Remove all migration if you want to start from sratch
`dotnet ef migrations remove`

Create a new entity framework migration
`dotnet ef migrations add InitialCreate`

Apply the migration to the database
`dotnet ef database update`