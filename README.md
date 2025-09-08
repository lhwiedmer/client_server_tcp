# client_server_tcp
Projeto para enviar arquivos de um cliente para um servidor por protocolo TCP.

A ideia é usar RSA para fazer uma autenticação inicial e AES para criptografar
os dados enviados de um lado para o outro.

Além disso, ele funcionará como se fosse numa rede local, usando WireGuard caso
seja necessário fazer a comunicação por internet para garantir a segurança.
