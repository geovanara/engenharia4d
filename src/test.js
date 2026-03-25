const connection = require('./db');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
 
async function createUser(name, email, password, cpf) {
    //Validar se expirou o teste de 7 dias
    const hoje = new Date();

    const expira = new Date();
    expira.setDate(hoje.getDate() + 7);

    try {
        const senhaHash = await bcrypt.hash(password, 10);

        const cpfHash = crypto
        .createHash('sha256')
        .update(cpf)
        .digest('hex');

         connection.query(
        `INSERT INTO users 
        (name, email, password_hash, cpf_hash, status, access_expires_at) 
        VALUES (?,?,?,?, 'active', ?)`,
        [name, email, senhaHash, cpfHash, expira],
        //Teste para verificar se não houve duplicidade no email
        (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    console.log('Email já cadastrado! ');
                } else {
                    console.log('Erro:', err);
                }
            }else {
                console.log('Usuário criado com segurança ');
            }
    }

    );
} catch (error) {
    console.log('Erro ao criptografar', error);
}
}

///createUser('Geovana', 'geo2@email.com', '123456', '12345678900');
//createUser('Geo', 'geo999@email.com', '123456', '12345678900');

function login (email, password) {
    connection.query(
        'SELECT * FROM users WHERE email = ?',
        [email],    
        async (err, result) => {
            if (err) return console.log(err);

            if (result.length === 0) {
                console.log('Usuário não encontrado');
                return;
        }   

            const user = result[0];

            //Verificação de senha correta
            const senhaValida = await bcrypt.compare(password, user.password_hash);

            if (!senhaValida) {
                console.log('Senha incorreta');
                return;
            } 

            //Verificação do prazo de periodo grátis (7 dias)
            const hoje = new Date();
            const expira = new Date(user.access_expires_at);

            if (expira < hoje) {
                console.log('Acesso expirado');
                return;
            }

            //Criar token
            const token = crypto.randomBytes(32).toString('hex');

            connection.query(
                `UPDATE users 
                SET session_token = ?, session_issued_at = NOW()
                WHERE id = ?`,
                [token, user.id]
            );

            console.log('Login realizado! Acesso liberado');
            console.log('Token: ', token);
        }
    );

}
//createUser('Geovana', 'geo2@email.com', '123456', '12345678900');
//createUser('Geo', 'geo3@email.com', '123456', '12345678900');
//createUser('Rapha', 'geovanarafa665@gmail.com', '3934811', '50146292880');
createUser('Ana', 'Anarocha21@gmail.com', '0485596', '66636587156');

setTimeout(() => {
    login ('Anarocha21@gmail.com', '0485596');
},1000);

