# 🔐 Solución: Error "refusing to allow a Personal Access Token to create or update workflow"

Al hacer `git push`, GitHub rechaza porque tu **Personal Access Token (PAT)** no tiene el permiso `workflow`.

## Paso 1: Actualizar el PAT en GitHub

1. Ir a [github.com/settings/tokens](https://github.com/settings/tokens)
2. Buscar el token que estás usando (o crear uno nuevo)
3. Editar el token y marcar el scope **`workflow`**
4. Guardar

El scope `workflow` permite modificar archivos `.github/workflows/*.yml`.

## Paso 2: Actualizar el remote con el nuevo token

```bash
# Si usas HTTPS con token:
git remote set-url origin https://USUARIO:NUEVO_TOKEN@github.com/SenorJA/dashboard-ctf.git

# O mejor: usar GitHub CLI (gh)
gh auth login
# Sigue las instrucciones interactivas (elige HTTPS,登录 con token que tenga workflow scope)
```

## Paso 3: Re-push

```bash
git push --force origin main
```

## Alternativa: Usar SSH en lugar de HTTPS

```bash
# Generar clave SSH (si no tienes)
ssh-keygen -t ed25519 -f ~/.ssh/github -N ""

# Añadir a GitHub: https://github.com/settings/keys
cat ~/.ssh/github.pub
# → Copiar y pegar en "New SSH Key"

# Cambiar remote
git remote set-url origin git@github.com:SenorJA/dashboard-ctf.git

# Probar
ssh -T git@github.com
git push --force origin main
```

## Resumen

| Cosa | Acción |
|------|--------|
| **Error** | `refusing to allow a PAT to create or update workflow` |
| **Causa** | El token no tiene scope `workflow` |
| **Solución** | [github.com/settings/tokens](https://github.com/settings/tokens) → marcar `workflow` |
| **Push final** | `git push --force origin main` (historia reescrita para eliminar secrets) |
