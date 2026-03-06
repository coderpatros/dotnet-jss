FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Directory.Build.props", "./"]
COPY ["src/CoderPatros.Jss.Web/CoderPatros.Jss.Web.csproj", "src/CoderPatros.Jss.Web/"]
COPY ["src/CoderPatros.Jss/CoderPatros.Jss.csproj", "src/CoderPatros.Jss/"]
RUN dotnet restore "src/CoderPatros.Jss.Web/CoderPatros.Jss.Web.csproj"
COPY src/CoderPatros.Jss.Web/ src/CoderPatros.Jss.Web/
COPY src/CoderPatros.Jss/ src/CoderPatros.Jss/
RUN dotnet publish "src/CoderPatros.Jss.Web/CoderPatros.Jss.Web.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM nginx:alpine AS final
COPY --from=build /app/publish/wwwroot /usr/share/nginx/html
EXPOSE 80
