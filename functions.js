		$(document).ready(function () {
			
			//***VARIABLES GLOBALES***

				//Variables para referenciar los datos ingresados por el usuario
					//contacto
					var referencia;
					var emailPrincipal = "";
					//General
					var vpn;
					//Network
					var publicaLocal;
					var publicaRemota;
					var natTraversal;
					var keepAlive;
					var dpd;
					//Authentication
					var authMethod;
					var psk;
					var signature;
					var ikeVersion;
					var ikeMode;
					//Phase1
					var phase1Proposal;			
					var phase1DiffieHellman;
					//Phase2
					var phase2Proposal;
					var phase2DiffieHellman;
					var localSubnet;
					var remoteSubnet;
					var phase2KeyLifetime;

				//Variables para referenciar los botones
					var anterior = $("#anterior");
					var siguiente = $("#siguiente");	
			    
				//clave para cifrar archivo de salida
					var clave;
				

				//Regex para validar email e IPs
					var emailRegex = /^[-\w.%+]{1,64}@(?:[A-Z0-9-]{1,63}\.){1,125}[A-Z]{2,63}$/i; 
					var ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/;
					var publicIpRegex = /^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
					var claseARegex = /^((?:10)\.)((?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){2}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/;
					var claseBRegex = /^(?:(?:172)\.)(?:(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)\.)((?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){1}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/;
					var claseCRegex = /^(?:(?:192)\.)(?:(?:168)\.)((?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){1}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/;
			
			//***FUNCIONES***		

			//verificar si todos los campos están completos
				function verificarCamposCompletos(divId) {
	    			var formularioCompleto = true;

	    			// Iterar a través de los elementos del formulario
	    			$("#" + divId + " input[required]").each(function() {
	      			// Verificar si el campo está vacío
	      			if ($(this).val() === '') {
	        			formularioCompleto = false;
	        			return false; // Romper el bucle si se encuentra un campo vacío
	      			}
	    		});

				if (divId=="phase2Proposal") {$("#randomize").prop('disbled', !formularioCompleto);}
	    		siguiente.prop('disabled', !formularioCompleto); //si no esta completo deshabilita el botón

    		}

    		//Verificar si el formato del email es correcto
    			function emailCorrecto () {
    				var correcto = false;
    				var email = $("#contactoEmailPrimario").val();
    				if(emailRegex.test(email)) {correcto = true;}

    				return correcto;
    			}

    		//verificar si el formato de la IP es correcto
    			function ipPublicaCorrecta (ip) {
    				var correcto = false;
    				if(publicIpRegex.test(ip)) {correcto = true;}

    				return correcto;
    			}	

			//verificar si la IP es publica
				function ipCorrecta (ip) {
					var correcto = false;
					if(ipRegex.test(ip)) {correcto = true;}

					return correcto;
				}	


				$("#randomKey").click (function () {  
					clave = generarRandom(22);
					$("#randomKey").val(clave);

				});
			//Asigna funcion al salir de los campos de Subnet en la Phase2, llama a la funcion para popular la lista de mascaras segun la subnet introducida	
				$(".subnet").blur(function () {
					var ip;
					var select;
					ip = $("#localSubnet").val();
					select = $("#localMask");
										

					if(this.getAttribute("id") == "remoteSubnet"){  //si se aplica a la subnet remota
						ip = $("#remoteSubnet").val();
						select = $("#remoteMask");
					}					

					if (ip !== ""){
						if(ipCorrecta(ip)){     //evalua que el formato de IP sea correcto
							if(ipPublicaCorrecta(ip)){   //evalua que sea una IP privada
								alert("Las subnets deben ser privadas"); //si es una IP publica da error
								return;														
							
							}
							else if (ip =="0.0.0.0") {
									select.empty();
									var maskList = [{id: "0.0.0.0", name: "/0"}]; // en caso de que la red sea 0.0.0.0 solo se permite mascara 0
									populate(select, maskList);
									select.attr('disabled','disabled');

								}else if($("#localSubnet").val() == $("#remoteSubnet").val()){
								alert("Las subnets no pueden ser iguales");
								} else if (claseARegex.test(ip)) {
									var maskList = [
												{id: "255.0.0.0", name: "/8"},{id: "255.128.0.0", name: "/9"},{id: "255.192.0.0", name: "/10"},
												{id: "255.224.0.0", name: "/11"},{id: "255.240.0.0", name: "/12"},{id: "255.248.0.0", name: "/13"},
												{id: "255.252.0.0", name: "/14"},{id: "255.254.0.0", name: "/15"},{id: "255.255.0.0", name: "/16"},
												{id: "255.255.128.0", name: "/17"},{id: "255.255.192.0", name: "/18"},{id: "255.255.224.0", name: "/19"},
												{id: "255.255.240.0", name: "/20"},{id: "255.255.248.0", name: "/21"},{id: "255.255.252.0", name: "/22"},
												{id: "255.255.254.0", name: "/23"},{id: "255.255.255.0", name: "/24"},{id: "255.255.255.128", name: "/25"},
												{id: "255.255.255.192", name: "/26"},{id: "255.255.255.224", name: "/27"},{id: "255.255.255.240", name: "/28"},
												{id: "255.255.255.248", name: "/29"},{id: "255.255.255.252", name: "/30"},{id: "255.255.255.254", name: "/31"},
												{id: "255.255.255.255", name: "/32"}
											];
									select.empty();		
									populate(select, maskList);
								}
								else if (claseBRegex.test(ip)) {
									var maskList = [
												{id: "255.255.0.0", name: "/16"},{id: "255.255.128.0", name: "/17"},{id: "255.255.192.0", name: "/18"},
												{id: "255.255.224.0", name: "/19"},{id: "255.255.240.0", name: "/20"},{id: "255.255.248.0", name: "/21"},
												{id: "255.255.252.0", name: "/22"},{id: "255.255.254.0", name: "/23"},{id: "255.255.255.0", name: "/24"},
												{id: "255.255.255.128", name: "/25"},{id: "255.255.255.192", name: "/26"},{id: "255.255.255.224", name: "/27"},
												{id: "255.255.255.240", name: "/28"},{id: "255.255.255.248", name: "/29"},{id: "255.255.255.252", name: "/30"},
												{id: "255.255.255.254", name: "/31"},{id: "255.255.255.255", name: "/32"}
											];
									select.empty();		
									populate(select, maskList);
								}
								else {
									maskList = [
												{id: "255.255.255.0", name: "/24"},{id: "255.255.255.128", name: "/25"},{id: "255.255.255.192", name: "/26"},
												{id: "255.255.255.224", name: "/27"},{id: "255.255.255.240", name: "/28"},{id: "255.255.255.248", name: "/29"},
												{id: "255.255.255.252", name: "/30"},{id: "255.255.255.254", name: "/31"},{id: "255.255.255.255", name: "/32"}
											];
									select.empty();		
									populate(select, maskList);		
								}
							}
								} else {alert("Por favor introduzca un formato de IP válido");}		


				});
			
			//Generar lista de mascaras de red disponibles segun la IP seleccionada	
				function populate (select, masks){
						var mask;
					for (var i = 0; i < masks.length; i++) {
						mask = masks[i];
						select.append($('<option></option>').val(mask.id).text(mask.name));
					}

					select.removeAttr("disabled"); //habilita el select para elegir la 
				}

    		//asigna funcion a evento onInput en todos los inputs que tenga atributo required
				$('.formDiv input[required]').on('input', function() {
	    			var divId = $(this).closest('.formDiv').attr('id');
	    			verificarCamposCompletos(divId);
  				});

			//asigna funcion al clickear en "siguiente" - oculta div actual y pasa al siguiente
  				$("#siguiente").click (function (){
		
					name = (this).getAttribute("data-message");
					
					switch (name) {
						case "contacto": {
							if(emailCorrecto()){
								$("#contacto").attr("style","display:none");
								$("#general").removeAttr("style");
								$("#siguiente").attr("data-message", "general");
								$("#anterior").removeAttr("style");	
								$("#anterior").attr("data-message", "general")
								$("#siguiente").attr('disabled', 'disabled');
								verificarCamposCompletos("general");
								cargarDatos("contacto");
							}else { alert("Por favor ingrese un email valido");}
							break;
							}
						case "general": {
							$("#general").attr("style", "display: none");
							$("#network").removeAttr("style");
							$("#anterior").attr("data-message", "network");
							$("#siguiente").attr("data-message", "network");
							$("#siguiente").attr('disabled', 'disabled');
							verificarCamposCompletos("network");
							cargarDatos("general");							
							break;
							}
						case "network": {
								publicaLocal = $("#publicaLocal").val();
								publicaRemota = $("#publicaRemota").val();

								if(!ipCorrecta(publicaLocal) || !ipCorrecta(publicaRemota)){
									alert("Por favor verifique que ambas IPs tengan el formato correcto");
								}else if (!ipPublicaCorrecta(publicaLocal) || !ipPublicaCorrecta(publicaRemota)){
									alert("Por favor verifique que ambas IPs sean públicas");
								}else if (publicaLocal == publicaRemota){
									alert("Por favor introduzca dos IPs publicas distintas");
								}else {		
									cargarDatos("network");						
									$("#network").attr("style","display:none");
									$("#authentication").removeAttr("style");
									$("#anterior").attr("data-message", "authentication");
									$("#siguiente").attr("data-message", "authentication");
									$("#siguiente").attr('disabled', 'disabled');
									verificarCamposCompletos("authentication");
								} 
								break;
							}
						case "authentication": {
							$("#authentication").attr("style","display:none");
							$("#phase1Proposal").removeAttr("style");
							$("#anterior").attr("data-message", "phase1Proposal");
							$("#siguiente").attr("data-message", "phase1Proposal");
							verificarCamposCompletos("phase1Proposal");
							cargarDatos("authentication");
							break;
							}
						case "phase1Proposal": {
							$("#phase1Proposal").attr("style","display:none");
							$("#phase2Proposal").removeAttr("style");
							$("#anterior").attr("data-message", "phase2Proposal");
							$("#siguiente").attr("data-message", "phase2Proposal");
							$("#siguiente").attr('disabled', 'disabled');
							verificarCamposCompletos("phase2Proposal");
							cargarDatos("phase1Proposal");
							$(this).text("Finalizar"); // al pasar al ultimo div "siguiente" se convierte en "finalizar"
							break;
							}
						case "phase2Proposal": {
							cargarDatos("phase2Proposal");
							generarConfig();
						}
						}
					});
  			//asigna funcion al clickear en "anterior" - oculta div actual y vuelve al anterior	
  				$("#anterior").click (function (){
		
					name = (this).getAttribute("data-message");
					
					switch (name) {
						case "general": {
							$("#general").attr("style","display:none");
							$("#contacto").removeAttr("style");
							$("#anterior").attr("style", "display:none");
							$("#siguiente").attr("data-message", "contacto");
							verificarCamposCompletos("contacto");
							break;
							}
						case "network": {
							$("#network").attr("style","display:none");
							$("#general").removeAttr("style");
							$("#anterior").attr("data-message", "general");
							$("#siguiente").attr("data-message", "general");
							verificarCamposCompletos("general");
							break;
							}
						case "authentication": {
							$("#authentication").attr("style","display:none");
							$("#network").removeAttr("style");
							$("#anterior").attr("data-message", "network");
							$("#siguiente").attr("data-message", "network");
							verificarCamposCompletos("network");
							break;
							}
						case "phase1Proposal": {
							$("#phase1Proposal").attr("style","display:none");
							$("#authentication").removeAttr("style");
							$("#anterior").attr("data-message", "authentication");
							$("#siguiente").attr("data-message", "authentication");
							verificarCamposCompletos("general");
							break;
							}
						case "phase2Proposal": {
							$("#phase2Proposal").attr("style","display:none");
							$("#phase1Proposal").removeAttr("style");
							$("#anterior").attr("data-message", "phase1Proposal");
							$("#siguiente").attr("data-message", "phase1Proposal");
							$("#siguiente").text("Siguiente"); // Vuelve a tomar el texto de "siguiente"
							verificarCamposCompletos("phase1Proposal");
							break;
							}
						}	
					});

  				function cargarDatos (panel) {
  					
  					switch(panel) {
  						case "contacto": {
							referencia = $("referencia").val();
							break;
  						}
  						case "general": {
  							vpn = $("#vpnName").val();
  							break;
  						}
	  					case "network": {
	  						publicaLocal = $("#publicaLocal").val();
							publicaRemota = $("#publicaRemota").val();
							if($("#natTraversal").is(':checked')){
								natTraversal = "enable";
							}else {
								natTraversal = "disabled";
							}
							keepAlive = $("#keepAlive").val();
							dpd = $("#deadPeerDetection").val();
							break;
	  					}
		  				case "authentication": {
		  					authMethod = $("#authMethod").val();
							psk = $("#psk").val();
							signature = $("#signature").val();
							ikeVersion = $("#ikeVersion").val();
							ikeMode = $("#ikeMode").val();
							break;
		  				}
			  			case "phase1Proposal": {
			  				phase1Proposal = $("#phase1Proposal1").val() + " " + $("#phase1Proposal2").val() + " " +$("#phase1Proposal3").val();			
							phase1DiffieHellman = $("#phase1DiffieHellman1").val() + " " + $("#phase1DiffieHellman2").val() + " " + $("#phase1DiffieHellman3").val();
							break;
			  			}
				  		case "phase2Proposal": {
				  			phase2Proposal = $("#phase2Proposal1").val() + " " + $("#phase2Proposal2").val() + " " +$("#phase2Proposal3").val();	
							phase2DiffieHellman = $("#phase1DiffieHellman1").val() + " " + $("#phase1DiffieHellman2").val() + " " + $("#phase1DiffieHellman3").val();
							localSubnet = $("#localSubnet").val() + " " + $("#localMask").val();
							remoteSubnet = $("#remoteSubnet").val() + " " + $("#remoteMask").val();
							phase2KeyLifetime = $("#phase2KeyLifetime").val();
							break;	
				  		}
  					}
  				}

				function generarRandom() {
					const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
					const charactersLength = characters.length;
					let result = "";
						for (let i = 0; i < 22; i++) {
							result += characters.charAt(Math.floor(Math.random() * charactersLength));
						}

					return result;
				}

				function generarConfig(){
					var configuracion = 
`config vpn ipsec phase1-interface
	edit "${vpn}"
	  set interface "wan1"
	  set dpd ${dpd}
	  set local-gw ${publicaLocal}
	  set dhgrp ${phase1DiffieHellman}
	  set proposal ${phase1Proposal}
	  set keylife ${keepAlive}
	  set remote-gw ${publicaRemota}
	  set psksecret ${psk}
	next
end
config vpn ipsec phase2-interface
	edit "${vpn}"
		set phase1name "${vpn}"
		set dhgrp ${phase2DiffieHellman}
		set proposal ${phase2Proposal}
		set auto-negotiate enable
		set keylife ${phase2KeyLifetime}
		set src-subnet ${localSubnet}
		set dst-subnet ${remoteSubnet}
	next
end				
config router static
	edit 0
		set dstaddr ${remoteSubnet}
		set device "${vpn}"
	next
end`;
		alert(configuracion);	

		var clave = generarRandom(22);

		var encryptado = CryptoJS.AES.encrypt(configuracion,clave).toString();

		var desencryptado = CryptoJS.AES.decrypt(encryptado, clave).toString(CryptoJS.enc.Utf8);
		
		//Crear un objeto Blob con el contenido del texto
			var blob = new Blob([encryptado], { type: 'text/plain' });

			// Crear un enlace de descarga
			var enlaceDescarga = document.createElement('a');
			enlaceDescarga.href = window.URL.createObjectURL(blob);
			enlaceDescarga.download = 'vpn_ipsec.txt';

			// Agregar el enlace al documento y simular un clic
			document.body.appendChild(enlaceDescarga);
			enlaceDescarga.click();

			// Eliminar el enlace del documento
			document.body.removeChild(enlaceDescarga);

			// Crear un objeto Blob con el contenido del texto
			var blob = new Blob([desencryptado], { type: 'text/plain' });

			// Crear un enlace de descarga
			var enlaceDescarga = document.createElement('a');
			enlaceDescarga.href = window.URL.createObjectURL(blob);
			enlaceDescarga.download = 'vpn_ipsec.txt';

			// Agregar el enlace al documento y simular un clic
			document.body.appendChild(enlaceDescarga);
			enlaceDescarga.click();

			// Eliminar el enlace del documento
				document.body.removeChild(enlaceDescarga);

				}
		});
