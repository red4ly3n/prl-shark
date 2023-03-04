
const express = require('express');
const app = express();
const morgan=require('morgan');
//Configuraciones
app.set('port', process.env.PORT || 3000);
app.set('json spaces', 2)
app.get('/', (req, res) => {    
    res.json(
        {
            "Title": "Hola mundo"
        }
    );
})

//Iniciando el servidor, escuchando...
app.listen(app.get('port'),()=>{
    console.log(`Server listening on port ${app.get('port')}`);
});

//Middleware
app.use(morgan('dev'));
app.use(express.urlencoded({extended:false}));
app.use(express.json());
 
