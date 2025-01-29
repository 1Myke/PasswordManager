from sympy import isprime, mod_inverse, nextprime, gcd
from sympy.ntheory.factor_ import primefactors
import random
import sqlite3

def lehen_erlatibo_txiki(m):
    zbki = 2
    while gcd(m, zbki) != 1:
        zbki += 1
    return zbki

def generate_primes():
    p = random.randint(10000, 1000000)
    q = random.randint(10000, 1000000)
    
    p = nextprime(p)
    q = nextprime(q)
    
    while p == q:
        q = nextprime(q + 1)
    
    return p, q

def RSA_gakoak():
    p, q = generate_primes()
    if isprime(p) and isprime(q):
        if p != q:
            n = p * q
            m = (p - 1) * (q - 1)
            r = lehen_erlatibo_txiki(m)
            s = mod_inverse(r, m)
            #print(f"Public key:({n},{r}) Privete key: ({s})")
        else:
            print("p and q cannot be the same number.")
    else:
        print("p and q are not prime numbers.")
    return n, r

def kodetu(txt):
    return [ord(char) for char in txt]

def deskodetu(kodetxt):
    return ''.join([chr(num) for num in kodetxt])

def modpower(base, exp, mod):
    return pow(base, exp, mod)

def zifratu(kodebektorea, r, n):
    return [modpower(k, r, n) for k in kodebektorea]

def deszifratu(bektorezifratu, s, n):
    return [modpower(b, s, n) for b in bektorezifratu]

def cifrador(testua, n, r):
    return zifratu(kodetu(testua), r, n)

def crackeador(bektorezifratu1, r, n):
    p, q = primefactors(n)
    m = (p - 1) * (q - 1)
    s = mod_inverse(r, m)
    emaitza = deszifratu(bektorezifratu1, s, n)
    return deskodetu(emaitza)

"""
print("Ejemplo de uso")
n = 59713
r = 11
mezu_sekreto = "cochetruco"
sec0 = cifrador(mezu_sekreto, n, r)
print(f"Mensaje cifrado: {sec0}")

emaitza = crackeador(sec0, r, n)
print(f"Mensaje descifrado: {emaitza}")

print("Otra prueba con otras claves")
n1, r1=RSA_gakoak()
sec = input("Insert the password you want to encrypt: ")
cifrado = cifrador(sec, n1, r1)
print(f"Mensaje cifrado: {cifrado}")

emaitza = crackeador(cifrado, r1, n1)
print(f"Mensaje descifrado: {emaitza}")
"""

# INTERFAZ GRAFICA DE EL GESTOR DE CONTRASEÑAS
import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import ttk  # Usar ttk para widgets con mejor estilo
import os 
import csv

# Crear la ventana principal con mejor diseño
def ventana_principal():
    root = tk.Tk()
    root.title("Gestor de Contraseñas by Mykx")
    root.geometry("400x300")  # Cambiar el tamaño de la ventana
    root.configure(bg="#f2f2f2")  # Cambiar el color de fondo

    # Título en la ventana
    titulo = ttk.Label(root, text="Gestor de Contraseñas", font=("Helvetica", 18, "bold"), background="#f2f2f2")
    titulo.pack(pady=20)

    # Crear un frame para los botones
    frame_botones = ttk.Frame(root)
    frame_botones.pack(pady=20)

    # Crear botones para las acciones principales con estilos
    btn_add = ttk.Button(frame_botones, text="Añadir nueva contraseña", command=pedir_datos, style="Accent.TButton")
    btn_add.grid(row=0, column=0, padx=10, pady=10)

    btn_retrieve = ttk.Button(frame_botones, text="Recuperar contraseña", command=pedir_contraseña, style="Accent.TButton")
    btn_retrieve.grid(row=0, column=1, padx=10, pady=10)

    btn_view = ttk.Button(frame_botones, text="Ver contraseñas guardadas", command=mostrar_contraseñas, style="Accent.TButton")
    btn_view.grid(row=1, column=0, padx=10, pady=10)

    btn_act = ttk.Button(frame_botones, text="Actualizar contraseña", command=pedir_actualizacion, style="Accent.TButton")
    btn_act.grid(row = 1, column = 1, padx = 10, pady = 10)

    btn_del = ttk.Button(frame_botones, text="Eliminar una cuenta", command=pedir_eliminacion, style="Accent.TButton")
    btn_del.grid(row = 2, column = 0, columnspan = 2, pady = 10)

    # Función para cerrar la aplicación
    def cerrar_aplicacion():
        if messagebox.askokcancel("Salir", "¿Seguro que deseas cerrar la aplicación?"):
            root.destroy()  # Esto cerrará la ventana principal y terminará la aplicación

    # Crear un botón para cerrar la aplicación
    boton_cerrar = tk.Button(root, text="Cerrar", command=cerrar_aplicacion)
    boton_cerrar.pack(pady=10)

    root.mainloop()

def mostrar_contraseñas():
    cargar_desde_txt('passwords.txt')
    ventana = tk.Toplevel()
    ventana.title("Contraseñas Guardadas")
    ventana.geometry("400x300")
    ventana.configure(bg="#e6e6e6")

    for fila in matriz:
        etiqueta = ttk.Label(ventana, text=f"Website: {fila[0]}, Usuario: {fila[1]}", background="#e6e6e6")
        etiqueta.pack(pady=5)

# Crear una matriz para almacenar los datos
matriz = []

# Función para agregar datos a la matriz
def agregar_datos(website, username, password, n, r):
    for fila in matriz:
        if fila[0] == website and fila[1] == username:
            messagebox.showinfo("Mykx Info", f"El usuario '{username}' ya existe para el sitio '{website}'.")
            return  # Si ya existe, no agregar duplicado

    # Si no existe duplicado, agregar los datos a la matriz
    matriz.append([website, username, password, n, r])
    messagebox.showinfo("Mykx Info", f"Datos agregados para el sitio '{website}' y el usuario '{username}'.")


# Función para guardar la matriz en un archivo de texto
def guardar_en_txt(nombre_archivo):
    # Abrir el archivo en modo 'w' para sobrescribir el contenido anterior
    with open(nombre_archivo, 'w', newline='') as archivo:
        escritor = csv.writer(archivo, delimiter='\t')
        
        # Escribir el encabezado
        escritor.writerow(["Website", "Username", "Password", "random numb (n)", "random numb (r)"])
        
        # Escribir los datos de la matriz
        escritor.writerows(matriz)

def cargar_desde_txt(nombre_archivo):
    matriz.clear()  # Limpiar la matriz antes de cargar los nuevos datos
    if os.path.exists(nombre_archivo):
        with open(nombre_archivo, 'r') as archivo:
            lector = csv.reader(archivo, delimiter='\t')
            next(lector)  # Saltar la primera fila con los encabezados
            for fila in lector:
                # Convertir la cadena de la lista en una lista de enteros
                fila[2] = eval(fila[2])  # Convertir la contraseña cifrada de string a lista
                fila[3] = int(fila[3])   # Asegurar que n sea un entero
                fila[4] = int(fila[4])   # Asegurar que r sea un entero
                matriz.append(fila)
                
# Funcion para pedir los datos que va a agregar luego a la matriz
def pedir_datos():
    root = tk.Tk()
    root.withdraw()

    website = simpledialog.askstring("Input", "Enter the website:", parent=root)
    username = simpledialog.askstring("Input", "Enter the username/email:", parent=root)
    password = simpledialog.askstring("Input", "Enter the password:", parent=root)

    # Hacer el cifrado de la contraseña antes de guardarla
    nPassword, rPassword = RSA_gakoak()
    encode = cifrador(password, nPassword, rPassword)

    # Cargar los datos del archivo antes de verificar duplicados
    cargar_desde_txt('passwords.txt')

    # Agregar los datos a la matriz (con verificación de duplicados)
    agregar_datos(website, username, encode, nPassword, rPassword)
    
    # Guardar en el archivo después de agregar a la matriz
    guardar_en_txt('passwords.txt')


#Funcion para recuperar la contraseña
def recuperar_contraseña(website, username):
    for fila in matriz:
        if fila[0] == website and fila[1] == username:
            return fila[2], fila[3], fila[4]
    return None, None, None

def pedir_contraseña():
    root = tk.Tk()
    root.withdraw()
    website = simpledialog.askstring("input", "Enter the website to retrieve the password: ", parent=root)
    username = simpledialog.askstring("input","Enter the username/email to retrieve the password: ", parent=root)
    
    # Recupera la contraseña cifrada, n, y r desde la matriz
    contraseña, n, r = recuperar_contraseña(website, username)
    
    if contraseña:
        # Descifrar la contraseña usando n y r
        contraseña_decoded = crackeador(contraseña, r, n)
        messagebox.showinfo("Mykx Info", f"La contraseña para {website} y {username} es: {contraseña_decoded}")
    else:
        messagebox.showinfo("Mykx Info","No se encontró la contraseña para el sitio web y usuario proporcionados.")
    
# Ejemplo de uso
"""
pedir_datos()
cargar_desde_txt('passwords.txt')
pedir_contraseña()
"""

# NUEVOS METODOS DE ACTUALIZAR Y BORRAR

def actualizar_contraseña(website, username, new_password):
    encontrado = False
    for fila in matriz:
        if fila[0] == website and fila[1] == username:
            nPassword, rPassword = RSA_gakoak()  # Genera nuevas claves para cifrar la nueva contraseña
            nueva_contraseña_cifrada = cifrador(new_password, nPassword, rPassword)
            fila[2] = nueva_contraseña_cifrada  # Actualiza la contraseña cifrada
            fila[3] = nPassword  # Actualiza el valor de n
            fila[4] = rPassword  # Actualiza el valor de r
            encontrado = True
            messagebox.showinfo("Mykx Info", f"Contraseña actualizada para {website} y {username}.")
            break
    
    if not encontrado:
        messagebox.showinfo("Mykx Info", f"No se encontró un registro para {website} y {username}.")
    
    # Guardar los cambios en el archivo
    guardar_en_txt('passwords.txt')

def pedir_actualizacion():
    root = tk.Tk()
    root.withdraw()
    website = simpledialog.askstring("input", "Enter the website to retrieve the password: ", parent=root)
    username = simpledialog.askstring("input","Enter the username/email to retrieve the password: ", parent=root)
    newPassword = simpledialog.askstring("Input", "Enter the new password:", parent=root)
    actualizar_contraseña(website, username, newPassword)

def eliminar_contraseña(website, username):
    encontrado = False
    for fila in matriz:
        if fila[0] == website and fila[1] == username:
            matriz.remove(fila)  # Elimina la fila de la matriz
            encontrado = True
            messagebox.showinfo("Mykx Info", f"El registro para {website} y {username} ha sido eliminado.")
            break
    
    if not encontrado:
        messagebox.showinfo("Mykx Info", f"No se encontró un registro para {website} y {username}.")
    
    # Guardar los cambios en el archivo
    guardar_en_txt('passwords.txt')

def pedir_eliminacion():
    root = tk.Tk()
    root.withdraw()
    website = website = simpledialog.askstring("input", "Enter the website to retrieve the password: ", parent=root)
    username = simpledialog.askstring("input","Enter the username/email to retrieve the password: ", parent=root)
    eliminar_contraseña(website, username)

ventana_principal()

#### CONTRASEÑA PARA ACCEDER A LA APLICACION?????