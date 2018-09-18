// 	***************************************************************************	
// 	* declaración de variables (de ser necesario, reemplazar los valores acá) *
// 	***************************************************************************

var IP_tdserver = "172.16.0.2";  			// default: 172.16.0.2

var MAC = "AABBCCDDEEFF";					// hay que crear una cuenta alumno para una MAC (recomendado de una netbook en desuso).

var Contrasena = "Alumno.";					// va la contraseña generada para la cuenta del alumno de la MAC elegida.

var ContrasenaEncriptada = false;			// (true/false) default: false 
											// Para versiones mas recientes del TDSERVER cambiar a true, caso contrario no ser podrá hacer log-in.
											
var pedirSerie = true;						// Solicitar que el alumno ingrese el numero de serie de la netbook. (true/false) default: false


var usarBD = false;							// usar una base de datos MySQL para registrar los desbloqueos diarios.

var DB_IP = "127.0.0.1";					// default: 172.16.0.2  IP del servidor de MySQL
var DB_usuario = "tdserveralu"; 			// usuario
var DB_basededatos = "tdserveralumno";		// default: 172.16.0.2  IP del servidor de MySQL
var DB_contrasena = "tdserveralumno_pass";	// default: 172.16.0.2  IP del servidor de MySQL
var DB_puerto = "3306";						// default: 3306  Puerto de conexion al servidor de MySQL
