""""Escribe una función que valide si una contraseña es “fuerte”.
Define tus propias reglas (mínimo 8 caracteres, al menos una mayúscula, etc.)."""


class PasswordWeakError(Exception):
   """Excepción lanzada cuando la contraseña no cumple los requisitos de seguridad."""
   pass


# Función que muestra los requisitos a la hora de establecer una contraseña segura.


def mostrar_requisitos():


   """Funcion que muestra los requisitos de una contraseña segura"""


   print("REQUISITOS CONTRASEÑA SEGURA")
   print("La contraseña debe tener al menos 8 caracteres ")
   print("La contraseña debe tener al menos una letra mayúscula")
   print("La contraseña debe tener al menos un número")
   print("La contraseña debe tener al menos uno de estos caracteres: _ # *")


# Crear función que pide datos o inputs usuario.


def pedir_información():


   """Esta función se encarga de pedir los datos al usuario"""


   contraseña = input("Introduce una contraseña segura  ")


   return contraseña


# Crear una función que valide la contraseña para comprobar si es fuerte


def comprobar_contraseña(contraseña):
   """Función que comprueba si la contraseña introducida es correcta en
   función de unos parametros"""


   if len(contraseña)<8: # Comprobar la longitud de la contraseña mayor 8 caracteres
      
       raise PasswordWeakError (" ❌ La contraseña debe tener al menos 8 caracteres ")
  
   tiene_mayuscula = False
   tiene_numero = False
   caracteres_especiales = "_#*@"
   tiene_especial = False


   for letra in contraseña:
       if letra.isupper():
           tiene_mayuscula = True
       if letra.isdigit():
           tiene_numero = True
       if letra in caracteres_especiales:
           tiene_especial = True


   if not tiene_mayuscula:     
        raise PasswordWeakError (" ❌ La contraseña debe tener al menos una letra mayúscula")
   if not tiene_numero:
       
        raise PasswordWeakError (" ❌ La contraseña debe tener al menos un número")
   if not tiene_especial:  
        raise PasswordWeakError (" ❌ La contraseña debe tener al menos uno de estos caracteres: _ # *")
  
 
   return True


  


# Creo función que imprime el resultado


def imprimir(resultado, mensaje):
 if resultado:
     print("✅", mensaje)
 else:
      print( mensaje)


# Creo función principal


def main():
  mostrar_requisitos()
  while True:
   contraseña= pedir_información()
   try:
       if comprobar_contraseña(contraseña):
           print("✅ Contraseña correcta.")
           break


   except PasswordWeakError as e:
       print(e)  # Muestra el mensaje de error detallado al usuario


# Caso de uso


main()