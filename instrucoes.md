### Configurando banco de dados
- Instalar o [Postgres 17.0](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads)
  - Durante a instalação, configurar a senha do usuário `postgres` como `12345`
  - Abrir **PgAdmin** e clicar em **Add New Server**
    - Em **General**:
        - Name: `app_server`
    - Em **Connection**:
      - Host name/address: `127.0.0.1`
      - Port: `5432`
      - Maintenance database: `postgres`
      - Username: `postgres`
      - Password: `12345`
    - Clicar em **Save**
  - Clicar com o botão direito em **Databases** e selecionar **Create Database**
    - Database: `app_db`
    - Owner: `postgres`
    - Clicar em **Save**
  - Clicar com o botão direito em **app_db** e selecionar **Query Tool**
    - Executar o script abaixo para criar a tabela de Usuarios:
      ```sql
        create table usuarios(
          id serial primary key ,
          email varchar(255) not null,
          senha varchar(255) not null
        );
      ```
    - Executar o script abaixo para criar a tabela de Alimentos
      ```sql
        create table alimentos(
          id serial primary key,
          nome varchar(255) not null,
          porcao integer not null,
          calorias integer not null,
          carboidratos integer not null,
          proteinas integer not null,
          gorduras integer not null,
          acucar integer not null,
          gordura_saturada integer not null,
          gordura_trans integer not null,
          fibras integer not null,
          sodio integer not null
        );
      ```
    - Executar o script abaixo para popular Alimentos
        ```sql
         insert into alimentos (nome, porcao, calorias, carboidratos, proteinas, gorduras, acucar, gordura_saturada, gordura_trans, fibras, sodio)
          values ('Big Mac', 216, 499, 42, 26, 25, 9.7, 9.9, 6.1, 3.7, 0.867),
           ('Batata Frita Media (McDonald''s)', 100, 295, 35, 5, 15, 0, 2.3, 0.4, 0, 0.284),
           ('Cheddar McMelt', 181, 505, 32, 29, 7.6, 14, 9.6, 4, 3.6, 0.876),
           ('Cheeseburger', 210, 302, 30, 16, 13, 8.6, 7, 0.4, 2, 0.73),
           ('Fini Dentaduras', 100, 354, 83, 5, 2, 56, 0, 0.9, 0, 0.046),
           ('Pão Francês', 50, 111, 23, 3.4, 0, 0.9, 0, 0, 0.9, 0.25),
           ('Alface', 100, 2, 0.97, 0.9, 0.4, 1.76, 0, 0.018, 1.2, 0.01),
           ('Cebola', 100, 42, 10.11, 0.92, 0.08, 4.28, 0, 0.026, 1.4, 0.003),
           ('Queijo Prato', 100, 353, 0.6, 8.3, 37.5, 5.7, 0, 0, 0, 0.12),
           ('Banana', 100, 89, 22.84, 1.09, 0.33, 12.23, 0, 0.112, 2.6, 0.001),
           ('Arroz Branco', 100, 130, 28.17, 2.69, 0.28, 0.05, 0, 0.176, 0, 0.365),
           ('Feijão Preto', 100, 132, 23.71, 8.86, 0.54, 0, 0, 0.139, 8.7, 0.001),
           ('Batata Doce', 100, 86, 20.12, 1.57, 0.05, 4.18, 0, 0.018, 3, 0.055),
           ('Macarrão', 100, 157, 30.68, 5.76, 0.92, 0.56, 0, 0.175, 1.3, 0.232),
           ('Coca Cola', 200, 85, 21, 0, 0, 21.18, 0, 0, 0, 0.01),
           ('Carne Vermelha', 100, 287, 0, 26.41, 19.29, 0, 7.631, 0, 0, 0.384),
           ('Carne de Porco', 100, 271, 0, 27.34, 17.04, 0, 6.168, 0, 0, 0.384);
        ```
      

### Configurando a API
- Clonar o repositório: `git clone https://github.com/plramoss/api_rn_estacio.git`
- Acessar a pasta do projeto: `cd api_rn_estacio` ou simplesmente abrir na IDE
- Instalar as dependências: `npm install`
- Criar JWT secret: `node generate-jwt-key.js`
- Iniciar a aplicação: `node app.js`
- Acessar a documentação da API: `http://localhost:3000/api/docs`

### Configurando o Frontend
- Clonar o repositório: `git clone https://github.com/plramoss/ext_proj_estacio.git`
- Acessar a pasta do projeto: `cd ext_proj_estacio` ou simplesmente abrir na IDE
- Instalar as dependências: `npm install`
- Alterar a linha 18 do arquivo `app/context/AuthContext.js` com o IP da máquina que está rodando a API
  - Para descobrir o IP da máquina, basta abrir o terminal e digitar `ipconfig` e procurar pelo IPv4 Address 
- Iniciar a aplicação: `npx expo start`

### Criando componentes e rotas
- Cada tela deve ser criada em `app/screens` e cada componente em `app/components`
- Para criar uma nova tela, basta criar um novo arquivo na pasta `app/screens` e importar o componente desejado
- Para criar a rota da tela criada, abrir o arquivo `App.tsx` e criar um `Stack.Screen` dentro do escopo condicional de autenticação
- Nova Rota
  - Exemplo:
    ```tsx
     <Stack.Screen
       name="NovaTela"
       component={NovaTela}
       options={{
         title: 'Nova Tela'
       }}
     />
    ```
- Exemplo de como ficaria o arquivo `App.tsx` com uma nova rota:
  ```tsx
    {authState?.authenticated ? (
      <>
        /* Rota já existente */
        <Stack.Screen
          name="Home"
          component={Home}
          options={{
            headerRight: () => <Button title="Logout" onPress={onLogout} />
          }}
        />
        /* Nova rota */
        <Stack.Screen
          name="NovaTela"
          component={NovaTela}
          options={{
            title: 'Nova Tela'
          }}
        />
      </>
    ) : (<>...</>)}
  ```
