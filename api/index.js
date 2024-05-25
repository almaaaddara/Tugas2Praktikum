const express = require("express");
const app = express();
const cors = require("cors");
const bodyParser = require ('body-parser');
// const { route } = require("./routes");
// const router = require("./routes");

const port = 8000;

app.use(cors());
app.use(bodyParser.json());
// app.use(router)
// app.use(express.json());

app.listen(port, function (){
    try {
        // await sequelize.authenticate();
        // console.log('Connection has been established successfully.');
        return console.log(`Server berjalan di port ${port}`);
      } catch (error) {
        console.log('Unable to connect to the database:');
      }
});