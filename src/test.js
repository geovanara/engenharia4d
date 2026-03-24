const connection = require('./db');

function createUser(name, email, password, cpf) {
    //Validar se expirou o teste de 7 dias
    const hoje = new Date();
    const expira = new Date();
    expira.setDate(hoje.getDate() + 7);


    connection.query(
        `INSERT INTO users 
        (name, email, password_hash, cpf, status, access_expires_at) 
        VALUES (?,?,?,?, 'active', ?)`,
        [name, email, password, cpf, expira],
        //Teste para verificar se não houve duplicidade no email
        (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    console.log('Email já cadastrado! ');
                } else {
                    console.log('Erro:', err);
                }
            }else {
                console.log('Usuário criado com 7 dias grátis');
            }
        }
    );
}

///createUser('Geovana', 'geo2@email.com', '123456', '12345678900');
createUser('Geo', 'geo999@email.com', '123456', '12345678900');

function login (email, password) {
    connection.query(
        'SELECT * FROM users WHERE email = ?',
        [email],    
        (err, result) => {
            if (err) return console.log(err);

            if (result.length === 0) {
                console.log('Usuário não encontrado');
                return;
            }

            const user = result[0];

            //Verificação de senha
            if (user.password_hash !== password) {
                console.log('Senha incorreta');
                return;
            }   

            //Verificação do prazo de periodo grátis (7 dias)
            const hoje = new Date();
            const expira = new Date(user.access_expires_at);

            if (expira < hoje) {
                console.log('Acesso expirado');
            } else {
                console.log('Login realizado! Acesso liberado');
            }
        }
    );

}
//createUser('Geovana', 'geo2@email.com', '123456', '12345678900');
//createUser('Geo', 'geo3@email.com', '123456', '12345678900');
login('geo999@email.com', '123456');



