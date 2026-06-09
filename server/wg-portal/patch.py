#!/usr/bin/env python3
# RPN Direct fork patch: add protected "owner" role + GUI-managed admin to wg-portal v2.3.0
import re, sys

def apply(path, steps):
    with open(path, encoding="utf-8") as f:
        s = f.read()
    for desc, pattern, func, expected in steps:
        s2, n = re.subn(pattern, func, s)
        ok = (n >= 1) if expected is None else (n == expected)
        if not ok:
            print("FAIL  %-28s %s : got %d (want %s)" % (path.split('/')[-1], desc, n, expected))
            sys.exit(1)
        print("ok    %-28s %s (%d)" % (path.split('/')[-1], desc, n))
        s = s2
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)

B = "/root/wg-portal-build"

# ---- snippets (Go) ----
IS_OWNER_METHOD = (
    "\n\n// IsOwner reports whether the identifier is a configured protected owner (RPN Direct fork).\n"
    "func (a *Auth) IsOwner(identifier string) bool {\n"
    "\tfor _, o := range a.Owners {\n"
    "\t\tif strings.EqualFold(strings.TrimSpace(o), strings.TrimSpace(identifier)) {\n"
    "\t\t\treturn true\n"
    "\t\t}\n"
    "\t}\n"
    "\treturn false\n"
    "}\n"
)
MGR_HELPERS = (
    "// isOwner reports whether the identifier is a configured protected owner (RPN Direct fork).\n"
    "func (m Manager) isOwner(id domain.UserIdentifier) bool {\n"
    "\treturn m.cfg.Auth.IsOwner(string(id))\n"
    "}\n\n"
    "// actorIsOwnerOrSystem returns true if the actor is an owner or the internal system admin.\n"
    "func (m Manager) actorIsOwnerOrSystem(actorId domain.UserIdentifier) bool {\n"
    "\treturn m.isOwner(actorId) || actorId == domain.SystemAdminContextUserInfo().Id\n"
    "}\n\n"
)
VM_OWNER = (
    "\n\t// Owner protection (RPN Direct fork): a protected owner may only be demoted,\n"
    "\t// disabled or locked by another owner (or the system). Owners are always admins.\n"
    "\tif m.isOwner(old.Identifier) {\n"
    "\t\tif !m.actorIsOwnerOrSystem(currentUser.Id) {\n"
    "\t\t\tif !new.IsAdmin {\n"
    "\t\t\t\treturn fmt.Errorf(\"cannot remove admin rights of an owner: %w\", domain.ErrNoPermission)\n"
    "\t\t\t}\n"
    "\t\t\tif new.IsDisabled() {\n"
    "\t\t\t\treturn fmt.Errorf(\"cannot disable an owner: %w\", domain.ErrNoPermission)\n"
    "\t\t\t}\n"
    "\t\t\tif new.IsLocked() {\n"
    "\t\t\t\treturn fmt.Errorf(\"cannot lock an owner: %w\", domain.ErrNoPermission)\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t\tnew.IsAdmin = true\n"
    "\t}\n"
)
VD_OWNER = (
    "\n\tif m.isOwner(del.Identifier) && !m.actorIsOwnerOrSystem(currentUser.Id) {\n"
    "\t\treturn fmt.Errorf(\"cannot delete an owner: %w\", domain.ErrNoPermission)\n"
    "\t}\n"
)
AUTH_OWNER = (
    "\t// Owner protection (RPN Direct fork): configured owners are always admins.\n"
    "\tif a.cfg.IsOwner(string(existingUser.Identifier)) && !existingUser.IsAdmin {\n"
    "\t\texistingUser.IsAdmin = true\n"
    "\t\tisChanged = true\n"
    "\t}\n"
)
VUE_OWNER = ("\n            <span v-if=\"user.IsOwner\" class=\"badge bg-warning text-dark ms-1\" "
             "title=\"Owner\">Owner</span>")

# ---- config/auth.go ----
apply(B + "/internal/config/auth.go", [
    ("import strings", r'\t"regexp"\n', lambda m: '\t"regexp"\n\t"strings"\n', 1),
    ("Owners field", r'HideLoginForm bool `yaml:"hide_login_form"`',
     lambda m: m.group(0) + '\n\n\t// Owners are protected superusers (RPN Direct fork).\n\tOwners []string `yaml:"owners"`', 1),
])
with open(B + "/internal/config/auth.go", encoding="utf-8") as f:
    s = f.read()
if "func (a *Auth) IsOwner(" not in s:
    with open(B + "/internal/config/auth.go", "a", encoding="utf-8", newline="\n") as f:
        f.write(IS_OWNER_METHOD)
    print("ok    auth.go(config)             IsOwner method appended")

# ---- domain/user.go ----
apply(B + "/internal/domain/user.go", [
    ("IsOwner field", r'LinkedPeerCount int `gorm:"-"`',
     lambda m: m.group(0) + '\n\n\tIsOwner         bool `gorm:"-"` // configured protected owner (RPN Direct fork)', 1),
])

# ---- app/users/user_manager.go ----
apply(B + "/internal/app/users/user_manager.go", [
    ("import strings", r'\t"sync"\n', lambda m: '\t"strings"\n\t"sync"\n', 1),
    ("owner helpers", r'// region internal-modifiers', lambda m: MGR_HELPERS + m.group(0), 1),
    ("validateModifications guard",
     r'\tif currentUser\.Id == old\.Identifier && new\.IsLocked\(\) \{\n\t\treturn fmt\.Errorf\("cannot lock own user: %w", domain\.ErrInvalidData\)\n\t\}\n',
     lambda m: m.group(0) + VM_OWNER, 1),
    ("validateDeletion guard",
     r'\tif !currentUser\.IsAdmin \{\n\t\treturn domain\.ErrNoPermission\n\t\}\n',
     lambda m: m.group(0) + VD_OWNER, 1),
    ("enrichUser IsOwner", r'\tuser\.LinkedPeerCount = len\(peers\)\n',
     lambda m: m.group(0) + '\tuser.IsOwner = m.isOwner(user.Identifier)\n', 1),
])

# ---- api/v0/model/models_user.go ----
apply(B + "/internal/app/api/v0/model/models_user.go", [
    ("DTO IsOwner field", r'\tIsAdmin\s+bool\s+`json:"IsAdmin"`',
     lambda m: m.group(0) + '\n\tIsOwner     bool     `json:"IsOwner"`', 1),
    ("DTO IsOwner mapping", r'IsAdmin:\s+src\.IsAdmin,',
     lambda m: m.group(0) + '\n\t\tIsOwner:             src.IsOwner,', None),
])

# ---- auth/oauth_common.go : disable implicit admin sync (GUI-managed admin) ----
apply(B + "/internal/app/auth/oauth_common.go", [
    ("default is_admin -> empty", r'IsAdmin:\s+"admin_flag",', lambda m: 'IsAdmin:    "",', 1),
])

# ---- auth/auth.go : owners always admin on login ----
apply(B + "/internal/app/auth/auth.go", [
    ("login owner-admin guard", r'\n\tisChanged := false\n', lambda m: m.group(0) + AUTH_OWNER, 1),
])

# ---- frontend/src/views/UserView.vue : owner badge ----
apply(B + "/frontend/src/views/UserView.vue", [
    ("owner badge", r'<span v-else><i class="fa fa-circle-xmark" :title="\$t\(\x27users\.no-admin\x27\)"></i></span>',
     lambda m: m.group(0) + VUE_OWNER, 1),
])

print("\nALL PATCHES APPLIED OK")
