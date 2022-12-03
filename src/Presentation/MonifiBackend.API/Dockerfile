#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["src/Presentation/MonifiBackend.API/MonifiBackend.API.csproj", "src/Presentation/MonifiBackend.API/"]
COPY ["src/Modules/WalletModule/MonifiBackend.WalletModule.Application/MonifiBackend.WalletModule.Application.csproj", "src/Modules/WalletModule/MonifiBackend.WalletModule.Application/"]
COPY ["src/Modules/WalletModule/MonifiBackend.WalletModule.Domain/MonifiBackend.WalletModule.Domain.csproj", "src/Modules/WalletModule/MonifiBackend.WalletModule.Domain/"]
COPY ["src/Modules/Core/MonifiBackend.Core.Domain/MonifiBackend.Core.Domain.csproj", "src/Modules/Core/MonifiBackend.Core.Domain/"]
COPY ["src/Modules/Core/MonifiBackend.Core.Application/MonifiBackend.Core.Application.csproj", "src/Modules/Core/MonifiBackend.Core.Application/"]
COPY ["src/Modules/UserModule/MonifiBackend.UserModule.Infrastructure/MonifiBackend.UserModule.Infrastructure.csproj", "src/Modules/UserModule/MonifiBackend.UserModule.Infrastructure/"]
COPY ["src/Modules/UserModule/MonifiBackend.UserModule.Domain/MonifiBackend.UserModule.Domain.csproj", "src/Modules/UserModule/MonifiBackend.UserModule.Domain/"]
COPY ["src/Modules/Core/MonifiBackend.Core.Infrastructure/MonifiBackend.Core.Infrastructure.csproj", "src/Modules/Core/MonifiBackend.Core.Infrastructure/"]
COPY ["src/Framework/MonifiBackend.Data/MonifiBackend.Data.csproj", "src/Framework/MonifiBackend.Data/"]
COPY ["src/Modules/UserModule/MonifiBackend.UserModule.Application/MonifiBackend.UserModule.Application.csproj", "src/Modules/UserModule/MonifiBackend.UserModule.Application/"]
COPY ["src/Modules/WalletModule/MonifiBackend.WalletModule.Infrastructure/MonifiBackend.WalletModule.Infrastructure.csproj", "src/Modules/WalletModule/MonifiBackend.WalletModule.Infrastructure/"]
COPY ["src/Modules/PackageModule/MonifiBackend.PackageModule.Infrastructure/MonifiBackend.PackageModule.Infrastructure.csproj", "src/Modules/PackageModule/MonifiBackend.PackageModule.Infrastructure/"]
COPY ["src/Modules/PackageModule/MonifiBackend.PackageModule.Domain/MonifiBackend.PackageModule.Domain.csproj", "src/Modules/PackageModule/MonifiBackend.PackageModule.Domain/"]
COPY ["src/Modules/PackageModule/MonifiBackend.PackageModule.Application/MonifiBackend.PackageModule.Application.csproj", "src/Modules/PackageModule/MonifiBackend.PackageModule.Application/"]
RUN dotnet restore "src/Presentation/MonifiBackend.API/MonifiBackend.API.csproj"
COPY . .
WORKDIR "/src/src/Presentation/MonifiBackend.API"
RUN dotnet build "MonifiBackend.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "MonifiBackend.API.csproj" -c Release -o /app/publish


# Install the agent
RUN apt-get update && apt-get install -y wget ca-certificates gnupg \
&& echo 'deb http://apt.newrelic.com/debian/ newrelic non-free' | tee /etc/apt/sources.list.d/newrelic.list \
&& wget https://download.newrelic.com/548C16BF.gpg \
&& apt-key add 548C16BF.gpg \
&& apt-get update \
&& apt-get install -y newrelic-dotnet-agent \
&& rm -rf /var/lib/apt/lists/*

# Enable the agent
ENV CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER={36032161-FFC0-4B61-B559-F6C5D41BAE5A} \
CORECLR_NEWRELIC_HOME=/usr/local/newrelic-dotnet-agent \
CORECLR_PROFILER_PATH=/usr/local/newrelic-dotnet-agent/libNewRelicProfiler.so \
NEW_RELIC_LICENSE_KEY=NRAK-41EWWAE4C75CAUHJJCT2Y0E6T28 \
NEW_RELIC_APP_NAME=MonifiBackend.API

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MonifiBackend.API.dll"]