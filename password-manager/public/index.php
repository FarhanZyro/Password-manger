<?php
declare(strict_types=1);
session_start();

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/Encryption.php';
require_once __DIR__ . '/../src/User.php';
require_once __DIR__ . '/../src/PasswordGenerator.php';
require_once __DIR__ . '/../src/PasswordRecord.php';

$config = require __DIR__ . '/../config/config.php';
$db     = Database::getInstance($config['db'])->getConnection();
$enc    = new Encryption($config['pbkdf2_iterations']);
$msg    = ''; $msgType = 'info';
$rawKey = isset($_SESSION['raw_key']) ? base64_decode($_SESSION['raw_key'], true) : null;
$action = $_POST['action'] ?? '';

switch ($action) {
    case 'register':
        try {
            if ($_POST['password'] !== $_POST['confirm']) throw new Exception('Passwords do not match.');
            (new User($db, $enc, $config['bcrypt_cost']))->register($_POST['login'], $_POST['password']);
            $msg = 'Account created!'; $msgType = 'success';
        } catch (Exception $e) { $msg = $e->getMessage(); $msgType = 'error'; }
        break;

    case 'login':
        $user = new User($db, $enc, $config['bcrypt_cost']);
        if ($user->login($_POST['login'], $_POST['password'])) {
            $_SESSION['user_id'] = $user->getId();
            $_SESSION['login']   = $user->getLogin();
            $_SESSION['raw_key'] = base64_encode($user->getDecryptedKey());
            $rawKey = $user->getDecryptedKey();
            $msg = 'Welcome, ' . htmlspecialchars($user->getLogin()) . '!'; $msgType = 'success';
        } else { $msg = 'Invalid credentials.'; $msgType = 'error'; }
        break;

    case 'logout':
        session_destroy(); header('Location: index.php'); exit;

    case 'save_password':
        try {
            (new PasswordRecord($db, $enc, $_SESSION['user_id']))->save($_POST['site_name'], $_POST['password'], $rawKey);
            $msg = 'Saved!'; $msgType = 'success';
        } catch (Exception $e) { $msg = $e->getMessage(); $msgType = 'error'; }
        break;

    case 'delete_password':
        $rec = new PasswordRecord($db, $enc, $_SESSION['user_id']);
        if ($rec->loadById((int)$_POST['record_id'])) { $rec->delete(); $msg = 'Deleted.'; $msgType = 'success'; }
        break;

    case 'change_password':
        try {
            if ($_POST['new_password'] !== $_POST['confirm_new']) throw new Exception('Passwords do not match.');
            $row = $db->prepare('SELECT login FROM users WHERE id=? LIMIT 1');
            $row->execute([$_SESSION['user_id']]); $row = $row->fetch();
            $user = new User($db, $enc, $config['bcrypt_cost']);
            $user->login($row['login'], $_POST['old_password']);
            $user->changePassword($_POST['old_password'], $_POST['new_password']);
            $_SESSION['raw_key'] = base64_encode($user->getDecryptedKey());
            $msg = 'Password changed!'; $msgType = 'success';
        } catch (Exception $e) { $msg = $e->getMessage(); $msgType = 'error'; }
        break;
}

$loggedIn = isset($_SESSION['user_id']);
$records  = $loggedIn && $rawKey ? PasswordRecord::getAllForUser($db, $enc, $_SESSION['user_id']) : [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password Manager</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f4f4f5; margin: 0; }
  header { background: #18181b; color: #fff; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
  main { max-width: 860px; margin: 2rem auto; padding: 0 1rem; }
  .card { background: #fff; border: 1px solid #e4e4e7; border-radius: 8px; padding: 1.2rem; margin-bottom: 1.2rem; }
  .card h2 { font-size: .95rem; font-weight: 600; margin-bottom: .8rem; }
  .row { display: flex; gap: .6rem; flex-wrap: wrap; margin-bottom: .6rem; }
  .field { flex: 1; min-width: 130px; }
  label { font-size: .75rem; color: #71717a; display: block; margin-bottom: .2rem; }
  input[type=text], input[type=password] { width: 100%; padding: .45rem .7rem; border: 1px solid #d4d4d8; border-radius: 5px; font-size: .88rem; }
  button { padding: .45rem 1rem; border: none; border-radius: 5px; font-size: .85rem; cursor: pointer; font-weight: 500; }
  .p { background: #6366f1; color: #fff; }
  .s { background: #e4e4e7; }
  .d { background: #ef4444; color: #fff; }
  .sm { padding: .25rem .6rem; font-size: .78rem; }
  .msg { padding: .6rem 1rem; border-radius: 5px; margin-bottom: 1rem; font-size: .88rem; }
  .success { background: #dcfce7; color: #166534; }
  .error   { background: #fee2e2; color: #991b1b; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 1.2rem; }
  table { width: 100%; border-collapse: collapse; font-size: .86rem; }
  th { text-align: left; padding: .4rem .6rem; border-bottom: 2px solid #e4e4e7; font-size: .75rem; color: #71717a; text-transform: uppercase; }
  td { padding: .5rem .6rem; border-bottom: 1px solid #f4f4f5; vertical-align: middle; }
  .mono { font-family: monospace; }
  .muted { color: #71717a; font-size: .78rem; }
  .srow { display: flex; align-items: center; gap: .6rem; margin-bottom: .4rem; }
  .srow label { min-width: 80px; margin: 0; }
  .srow input[type=range] { flex: 1; }
  .srow .v { min-width: 20px; font-weight: 600; font-size: .82rem; }
  #out { font-family: monospace; background: #f4f4f5; padding: .5rem .8rem; border-radius: 5px; margin: .6rem 0; min-height: 2rem; font-size: 1rem; word-break: break-all; }
  #warn { color: #b45309; font-size: .78rem; min-height: 1rem; }
</style>
</head>
<body>
<header>
  <strong>🔐 Password Manager</strong>
  <?php if ($loggedIn): ?>
    <span style="font-size:.85rem;color:#a1a1aa">
      <?= htmlspecialchars($_SESSION['login']) ?>
      <form method="post" style="display:inline"><input type="hidden" name="action" value="logout">
        <button class="s sm" style="margin-left:.5rem">Log out</button></form>
    </span>
  <?php endif; ?>
</header>
<main>
<?php if ($msg): ?><div class="msg <?= $msgType ?>"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

<?php if (!$loggedIn): ?>
<div class="cols">
  <div class="card"><h2>Log in</h2>
    <form method="post"><input type="hidden" name="action" value="login">
      <div class="row"><div class="field"><label>Login</label><input type="text" name="login" required></div></div>
      <div class="row"><div class="field"><label>Password</label><input type="password" name="password" required></div></div>
      <button class="p">Log in</button>
    </form>
  </div>
  <div class="card"><h2>Register</h2>
    <form method="post"><input type="hidden" name="action" value="register">
      <div class="row"><div class="field"><label>Login</label><input type="text" name="login" required></div></div>
      <div class="row"><div class="field"><label>Password</label><input type="password" name="password" required></div></div>
      <div class="row"><div class="field"><label>Confirm</label><input type="password" name="confirm" required></div></div>
      <button class="p">Register</button>
    </form>
  </div>
</div>

<?php else: ?>
<div class="card"><h2>Password Generator</h2>
  <?php foreach ([['len','Length',4,64,12],['lower','Lowercase',0,64,3],['upper','Uppercase',0,64,3],['nums','Numbers',0,64,3],['spec','Special',0,64,3]] as [$id,$label,$min,$max,$val]): ?>
  <div class="srow"><label><?= $label ?></label>
    <input type="range" id="sl-<?= $id ?>" min="<?= $min ?>" max="<?= $max ?>" value="<?= $val ?>" oninput="sync()">
    <span class="v" id="v-<?= $id ?>"><?= $val ?></span>
  </div>
  <?php endforeach; ?>
  <div id="warn"></div><div id="out">—</div>
  <div style="display:flex;gap:.5rem">
    <button class="p" onclick="gen()">Generate</button>
    <button class="s" onclick="navigator.clipboard.writeText(document.getElementById('out').textContent)">Copy</button>
    <button class="s" onclick="document.getElementById('f-pw').value=document.getElementById('out').textContent">Use ↓</button>
  </div>
</div>

<div class="card"><h2>Save Password</h2>
  <form method="post"><input type="hidden" name="action" value="save_password">
    <div class="row">
      <div class="field"><label>Site</label><input type="text" name="site_name" placeholder="e.g. Gmail" required></div>
      <div class="field"><label>Password</label><input type="text" name="password" id="f-pw" required></div>
    </div>
    <button class="p">Save</button>
  </form>
</div>

<div class="card"><h2>Saved Passwords</h2>
  <?php if (empty($records)): ?><p class="muted">No passwords saved yet.</p>
  <?php else: ?>
  <table><thead><tr><th>Site</th><th>Password</th><th>Date</th><th></th></tr></thead><tbody>
  <?php foreach ($records as $rec): ?>
    <tr>
      <td><?= htmlspecialchars($rec->getSiteName()) ?></td>
      <td class="mono">
        <span data-pw="<?= htmlspecialchars($rec->getDecryptedPassword($rawKey)) ?>">••••••••</span>
        <button class="s sm" onclick="var s=this.previousElementSibling;s.textContent=s.textContent==='••••••••'?s.dataset.pw:'••••••••'">Show</button>
      </td>
      <td class="muted"><?= $rec->getCreatedAt()->format('Y-m-d H:i') ?></td>
      <td><form method="post" onsubmit="return confirm('Delete?')">
        <input type="hidden" name="action" value="delete_password">
        <input type="hidden" name="record_id" value="<?= $rec->getId() ?>">
        <button class="d sm">Del</button>
      </form></td>
    </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<div class="card"><h2>Change Password</h2>
  <form method="post"><input type="hidden" name="action" value="change_password">
    <div class="row">
      <div class="field"><label>Current</label><input type="password" name="old_password" required></div>
      <div class="field"><label>New</label><input type="password" name="new_password" required></div>
      <div class="field"><label>Confirm</label><input type="password" name="confirm_new" required></div>
    </div>
    <button class="p">Change</button>
  </form>
</div>
<?php endif; ?>
</main>
<script>
const G = id => document.getElementById(id);
function sync() {
  ['len','lower','upper','nums','spec'].forEach(k => G('v-'+k).textContent = G('sl-'+k).value);
  const sum = +G('sl-lower').value + +G('sl-upper').value + +G('sl-nums').value + +G('sl-spec').value;
  G('warn').textContent = sum !== +G('sl-len').value ? `⚠ Counts sum to ${sum}, length is ${G('sl-len').value}` : '';
}
function gen() {
  const L='abcdefghijklmnopqrstuvwxyz', U=L.toUpperCase(), N='0123456789', S='!@#$%^&*()-_=+[]{}|;:,.<>?';
  const ri = n => { const a=new Uint32Array(1); crypto.getRandomValues(a); return a[0]%n; };
  const pick = (s,n) => Array.from({length:n}, ()=>s[ri(s.length)]);
  const chars = [...pick(L,+G('sl-lower').value),...pick(U,+G('sl-upper').value),...pick(N,+G('sl-nums').value),...pick(S,+G('sl-spec').value)];
  for(let i=chars.length-1;i>0;i--){const j=ri(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}
  G('out').textContent = chars.join('');
}
</script>
</body>
</html>