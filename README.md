# client_server_tcp
Projeto para enviar arquivos de um cliente para um servidor por protocolo TCP.

A ideia é fazer uma verificação com assinatura e verificação inicial dos dois
com uma chave assimétrica e hash, depois gerar uma chave AES para criptografar
os dados enviados de um lado para o outro.

Essa chave AES será enviada pelo cliente cifrada com um algoritmo de encriptação
assimétrico.

Além disso, ele funcionará como se fosse numa rede local, usando WireGuard caso
seja necessário fazer a comunicação por internet para garantir a segurança.
