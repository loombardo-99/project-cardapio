<?php
session_start();

// Dados de conexão com o banco de dados
$servername = "localhost";
$username = "seu_usuario";
$password = "sua_senha";
$dbname = "seu_banco_de_dados";

// Cria a conexão
$conn = new mysqli($servername, $username, $password, $dbname);

// Verifica a conexão
if ($conn->connect_error) {
    die("Falha na conexão com o banco de dados: " . $conn->connect_error);
}

// Recebe os dados do formulário
$username = $_POST["username"]; // Usando o nome do usuário como "username"
$password = $_POST["password"];

// Prepara a consulta SQL
$sql = "SELECT UsuarioID, Nome, Senha, TipoUsuario FROM Usuarios WHERE Nome = ?"; // Buscamos o TipoUsuario
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $username);

// Executa a consulta
$stmt->execute();
$result = $stmt->get_result();

// Verifica se encontrou um usuário com o nome de usuário fornecido
if ($result->num_rows > 0) {
    // Obtém os dados do usuário
    $row = $result->fetch_assoc();
    $hashedPasswordFromDB = $row["Senha"];
    $tipoUsuario = $row["TipoUsuario"]; // Obtemos o tipo de usuário

    // Verifica se a senha fornecida corresponde à senha hasheada no banco
    if (password_verify($password, $hashedPasswordFromDB)) {
        // Login bem-sucedido

        // Armazena informações do usuário na sessão
        $_SESSION["UsuarioID"] = $row["UsuarioID"];
        $_SESSION["username"] = $row["Nome"];
        $_SESSION["TipoUsuario"] = $tipoUsuario; // Armazenamos o TipoUsuario na sessão

        // Redireciona para o painel apropriado com base no tipo de usuário
        if ($tipoUsuario == "admin") {
            header("Location: admin_dashboard.php");
            exit();
        } elseif ($tipoUsuario == "atendente") {
            header("Location: atendente_dashboard.php");
            exit();
        } else {
            // Tipo de usuário desconhecido
            echo "Tipo de usuário desconhecido."; // Tratar adequadamente em produção
            session_destroy(); // Limpar a sessão se algo estiver errado
            exit();
        }
    } else {
        // Senha incorreta
        echo "Usuário ou senha incorretos."; // Tratar adequadamente em produção
    }
} else {
    // Usuário não encontrado
    echo "Usuário ou senha incorretos."; // Tratar adequadamente em produção
}

// Fecha a conexão
$stmt->close();
$conn->close();
?>
Use code with caution.
PHP
4. Painel de Administração (admin_dashboard.php):
Verifique o TipoUsuario na sessão para garantir que apenas administradores acessem o painel.
<?php
session_start();

// Verifica se o usuário está logado E se é um administrador
if (!isset($_SESSION["UsuarioID"]) || $_SESSION["TipoUsuario"] != "admin") {
    header("Location: login.html"); // Redireciona para a página de login
    exit();
}

// Resto do código do painel de administração
// ...
?>