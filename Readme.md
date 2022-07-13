### API 1: Broken Object Level Authorization
**Descrição:** A falta de autorização nas chamadas dos _endpoints_, permitem que os atacantes busquem por esse endpoints e façam requisições obtendo informações importantes ou até mesmo sensíveis.

**Vetor de ataque:** Endpoints com falta de controle de acesso permitem que os atacantes busquem por informações que não deveriam ser acessadas.

**Prevenção:** Implementar se possível em todas as chamadas autenticação, para saber se o usuário que está utilizando realmente tem acesso a esse tipo de informação.

**Referência:** 
 - [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)
 - [CWE-284: Improper Access Control (4.5)](https://cwe.mitre.org/data/definitions/284.html)
 - [CWE-285: Improper Authorization (4.5)](https://cwe.mitre.org/data/definitions/285.html)
 - [CWE-639: Authorization Bypass Through User-Controlled Key (4.5)](https://cwe.mitre.org/data/definitions/639.html)

**Exemplo:** API que lista informações de um clinte (/shops/{shopName}/revenue_data.json), sem uma validação de quem está realizando a requisição o atacante pode buscar por informações de outros clientes.

**Correção:** Sempre utilizar de validação de requisição, para que informações sensíveis de outros usuários não vazem.
 

### API 2: Broken User Authentication
**Descrição:** A partir de uma falha na autenticação o atacante consegue utilizar de um usuário básico para conseguir informações que requerem um perfil de privilégio elevado ou de um outro perfil específico.

**Vetor de ataque:** Realizando alterações de _token_ ou de outros mecanismos o atacante consegue se passar por outro usuário que tem permissão para acessar aquelas informações.

**Prevenção:** Sempre que possível validar que aquele usuário pode realmente ter acesso aquelas informações, implementar autenticação forte, utilizar de autenticação em dois fatores entre outras.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [Key Management - OWASP Cheat Sheet Series](https://www.owasp.org/index.php/Key_Management_Cheat_Sheet)

- [Authentication - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

- [Credential stuffing Software Attack | OWASP Foundation](https://www.owasp.org/index.php/Credential_stuffing)

**Exemplo:** No _enpoint_ de resete de senha, / api / system / verification-codes / {smsToken}, é enviado um _token_ para o celular do usuário a partir de um sms, não tendo as proteções corretas o atacante consegue utilizar de um ataque de força bruta para adivinhar o _token_. 

**Correção:** Nesse caso implementar um _rate limit_, não sendo possível executar várias requisições.

 
### API 3: Excessive Data Exposure
**Descrição:** Informações excessivas tanto em tratamentos de erros das chamadas das API’s, quanto as informações que são enviadas para o processo padrão.

**Vetor de ataque:** Muitas vezes após alguns erros é possível identificar algumas informações, já que não existe um tratamento para o erro. Muitos casos os _endpoints_ passam mais informações que a aplicação necessita, isso da ferramentas para o atacante começar um ataque.

**Prevenção:** Questionar sobre os dados necessários, nunca delegar para o cliente filtrar os dados, utilizar métodos genéricos, tratar as respostas que são apresentadas para o usuário.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [CWE-213: Exposure of Sensitive Information Due to Incompatible Policies (4.5)](https://cwe.mitre.org/data/definitions/213.html)


**Exemplo:** Analisando o trafego de dados de um aplicativo, o invasor descobre um _enpoint_ que trás as informações da empresa para uma tela de busca, porém pelo tráfego de rede o _enpoint_ trás mais informações, contendo informações sensíveis da empresa.

**Correção:** Limitar as informações que são enviadas pelos _endpoints_, enviar apenas dados necessários para a aplicação, não utilizar métodos básicos.

 
### API 4: Lack of Resources & Rate Limiting
Descrição: Não ter um controle do número de requisições ou das informações que são enviadas pelos usuários.

**Vetor de ataque:** A falta do controle das requisições permite que o atacante realize um ataque onde ele abusa da falta de limite de requisições, onde ele consegue chamar inúmeras vezes o _endpoint_ obtendo informações ou até mesmo negando o serviço. Em um outro caso não ter um limite dos dados enviados pelo usuário pode ocasionar em um estouro de _buffer_, que pode resultar em informações para o atacante.

**Prevenção:** Impor limites para as requisições se possível de todos os _endpoints_, sanitizar os dados enviados pelos usuários.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [Blocking Brute Force Attacks Control | OWASP Foundation](https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks)

- [Git OWASP Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/3a8134d792528a775142471b1cb14433b4fda3fb/cheatsheets/Docker_Security_Cheat_Sheet.md#rule-7---limit-resources-memory-cpu-file-descriptors-processes-restarts)

- [Git OWASP Assessment Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/3a8134d792528a775142471b1cb14433b4fda3fb/cheatsheets/REST_Assessment_Cheat_Sheet.md)

**Exemplo:** A partir de uma requisição POST para / api / v1 / o atacante envia uma imagem muito grande, gerando um estouro de memória por conta do tamanho.

**Correção:** Para corrigir esse tipo de vulnerabilidade é necessário implementar métodos que validem o tipo e tamanho das informações enviadas.


### API 5: Broken Function Level Authorization
**Descrição:**  A falta de implementação de controle de acesso gera a falha, já que o atacante pode abusar disso e criar métodos para conseguir acessar as informações ou ações de administradores.

**Vetor de ataque:** Alterar o método, informação do usuário que está requisitando, burlando os acessos já que não tem o controle devido em todos os métodos.

**Prevenção:** Assegurar que todos os endpoints estão com seus controles de acesso configurados, de preferência todos os acessos devem ser negados e liberados de acordo com o perfil apenas as funcionalidades necessárias.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [Forced Browsing Software Attack | OWASP Foundation](https://www.owasp.org/index.php/Forced_browsing)

- [OWASP Top Ten Web Application Security Risks | OWASP](https://www.owasp.org/index.php/Top_10_2013-A7-Missing_Function_Level_Access_Control)

- [OWASP Access Control](https://www.owasp.org/index.php/Category:Access_Control)

**Exemplo:** A partir do _endpoint_ / api / convites / {invite_guid} que um atacante recebeu utilizando o sistema, a requisição para / api / convites / novo, alterando seu perfil para administrador, possibilitando ações de privilégio elevado.
```
POST /api/convites/novo

{“email”:”hugo@malicious.com”,”role”:”admin”}
```

**Correção:** Para esse caso validar as permissões dos _endpoints_, não permitir que usuários comuns realizem chamadas para esse _endpoint_ e faça requisições POST nesse _endpoint_.


### API 6: Mass Assignment
**Descrição:** Abusar de funcionalidades permitindo alterar valores de variáveis ou informações de configuração que permitam o atacante ter acesso privilegiado.

**Vetor de ataque:** A partir de uma falta de controle de acesso e modificação, o atacante pode realizar alterações de configuração elevando seu privilégio, ou alterando valores de variáveis para que ele seja beneficiado de alguma forma.

**Prevenção:** Evitar que seja permitido alterações de parâmetros dos clientes, definir e forçar a utilização de schemas entre outras

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (4.5)](https://cwe.mitre.org/data/definitions/915.html) 

**Exemplo:** Em um _endpoint_ de cadastro de usuário o atacante realiza uma requisição PUT com dados válidos, nesse mesmo _endpoint_ realiza um requisição GET e recebe um valor a mais de crédito em conta. A partir dessas informações realize um POST alterando o valor do crédito na sua conta.

**Correção:** Revisar valores que podem ser alterados por usuários e permissões de requisições.

 
### API 7: Security Misconfiguration
**Descrição:** Falha nas configurações de segurança, ou falta de configuração dos componentes de segurança.

**Vetor de ataque:** O atacante busca essas falhas/falta de configuração dos componentes de segurança visando informações que proporcionem um ataque direcionado, ou até mesmo uma elevação de privilégios.

**Prevenção:** Manter todas as configurações de segurança em dia, utilizar de componentes que automatizem a segurança, canal seguro para a comunicação entre outras.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

- [Git OWASP - Web Application Deployment Management](https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing)

- [Git OWASP - Web Application Error Handling](https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling)

- [Git OWASP - Web Application Cross Origin Resource](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client_Side_Testing/07-Testing_Cross_Origin_Resource_Sharing.md)

**Exemplo:** Pela falta de configuração de métodos de requisição, um atacante consegue alterar seu perfil para adiministrador podendo assim realizar ações de perfil elevado.

**Correção:** Validar as configurações de todos os _endpoints_.


### API 8: Injection
**Descrição:** A falta de sanitizar os dados enviados pelos usuários permite o envio de dados maliciosos.

**Vetor de ataque:** Utilizando de ferramentas para buscar essas falhas, os atacantes enviam dados maliciosos com o intuito de conseguir um acesso ao sistema, informações sensíveis ou elevação de privilégios.

**Prevenção:** Sempre sanitizar todos os dados que os usuários enviam, sempre que possível negar a utilização de caracteres especiais.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [Injection Flaws | OWASP](https://owasp.org/www-community/Injection_Flaws)

- [SQL Injection | OWASP](https://owasp.org/www-community/attacks/SQL_Injection)

- [OWASP-GOD16-NOSQL.pdf](https://www.owasp.org/images/e/ed/GOD16-NOSQL.pdf)

- [Command Injection | OWASP](https://owasp.org/www-community/attacks/Command_Injection)

**Exemplo:** Realizando uma avaliação no serviço o atacante descobre que em um dos _endpoints_ consegue enviar dados direto para o sistema, com isso ele injeta valores que não são sanitizados, resultando em uma negação de serviço.

**Correção:** Todos os dados enviados pelos usuários devem ser sanitizados e se possível impedir a utilização de alguns caracteres especiais.

 
### API 9: Improper Assets Management
**Descrição:** Falta de documentação e atualizações permitem que falhas gerando mais vetores de ataque.

**Vetor de ataque:** A falta da atualização de segurança permite com que o atacante tenha facilidade para burlar as seguranças, obtendo informações sensíveis ou até mesmo controle do servidor.

**Prevenção:** Manter todos os recursos documentados e atualizados.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [CWE-1059: Incomplete Documentation (4.5)](https://cwe.mitre.org/data/definitions/1059.html)

- [Home - OpenAPI Initiative](https://www.openapis.org/)


**Exemplo:** Após a alteração da versão de um _endpoint_ o desenvolvedor esqueceu de retirar a versão antiga, com isso o atacante tentou a requisição na versão 1, conseguindo informação sensíveis do banco de dados.

**Correção:** Para se proteger dessa vulnerabilidade, é recomendado utilizar ferramentas que realizar essa limpeza de código e funcionários mais experiêntes para validar que não está sendo enviado informações a mais para produção.


### API 10: Insufficient Logging & Monitoring
**Descrição:** Falta de registro das atividades e falta de monitoração nas atividades.

**Vetor de ataque:** Com a falta de monitoração e registro, é quase impossível detectar o atacante gerando tempo suficiente para ele planejar e estruturar um ataque direcionado.

**Prevenção:** Utilizar de ferramentas que realizem o trabalho de monitoramento e registrar se possível o máximo informações sobre o que acontece no sistema.

**Referência:** 
- [OWASP API Security - Top 10 | OWASP](https://owasp.org/www-project-api-security/)

- [CheatSheetSeries/Logging_Cheat_Sheet.md at master · OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Cheat_Sheet.md)

- [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/)

- [ASVS/0x15-V7-Error-Logging.md at master · OWASP/ASVS](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x15-V7-Error-Logging.md)

**Exemplo:** A partir de um vazamento de chave em um repositório público, a empresa ficou vulneravel por 48 horas até que o problema fosse corrigido, pela falta de monitoração e _logs_ não foi possível identificar o que foi afetado pelo invasor.

**Correção:** Implementar ferramentas de _logs_ e monitoramento, para que você tenha o maior controle possível de tudo que está sendo executado, enviado no seu sistema.
