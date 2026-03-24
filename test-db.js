const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'engenharia4d'
});

connection.connect((err) => {
  if (err) {
    console.log('Erro ao conectar:', err);
  } else {
    console.log('Conectado com sucesso!');
  }
});