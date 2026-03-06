FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Directory.Build.props", "./"]
COPY ["src/CoderPatros.Jss.Api/CoderPatros.Jss.Api.csproj", "src/CoderPatros.Jss.Api/"]
COPY ["src/CoderPatros.Jss/CoderPatros.Jss.csproj", "src/CoderPatros.Jss/"]
RUN dotnet restore "src/CoderPatros.Jss.Api/CoderPatros.Jss.Api.csproj"
COPY src/CoderPatros.Jss.Api/ src/CoderPatros.Jss.Api/
COPY src/CoderPatros.Jss/ src/CoderPatros.Jss/
RUN dotnet publish "src/CoderPatros.Jss.Api/CoderPatros.Jss.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "CoderPatros.Jss.Api.dll"]
