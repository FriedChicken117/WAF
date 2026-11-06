FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["WafProyecto.csproj", "./"]
RUN dotnet restore "WafProyecto.csproj"
COPY . .
RUN dotnet publish "WafProyecto.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "WafProyecto.dll"]