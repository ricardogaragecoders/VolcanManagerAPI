# Volcan Manager API REST


### Crear un API Key para Estrato
    api_key, key = CompanyAPIKey.objects.create_key(name="ApiKey CMF", company=company)


### Contenedor de Docker 

    docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 -e RABBITMQ_DEFAULT_USER=volcan_manager_api -e RABBITMQ_DEFAULT_PASS=S0m3P4ssw0rd -e RABBITMQ_DEFAULT_VHOST=volcan_manager_api_host rabbitmq:management