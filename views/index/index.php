<?php
$isLoggedIn = false;
$user_id = MiniEngine::getSession('user_id');
$user = null;
if (isset($user_id)) {
    $user = User::find($user_id);
    $isLoggedIn = isset($user);
}
?>
<?= $this->partial('common/header') ?>
<main>
  <div class="container" style="max-width: 1120px;">
    <div class="row pt-5 pb-4">
      <div class="col-md-4"></div>
        <div class="col-md-4">
          <?php if (!$isLoggedIn) { ?>
            <h1 class="mb-3 fs-2 fw-normal text-center">Enter username</h1>
            <form method="post" action="/auth">
              <div class="mb-3">
                <label for="username" class="form-label">使用者名稱</label>
                <input id="username" name="username" type="text" class="form-control">
              </div>
              <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
              <div class="text-center">
                <button type="submit" class="btn btn-primary">Submit</button>
              </div>
            </form>
          <?php } ?>
          <?php if ($isLoggedIn) { ?>
            <p class="mb-3 fs-2 ">Hello <span class="fw-semibold"><?= $this->escape($user->displayname) ?></span></p>
            <div class="card mb-3">
              <div class="card-body">
                <h2 class="mb-3 fs-5 card-title">基本功能</h2>
                <form action="/auth/logout" method="POST">
                  <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
                  <button type="submit" class="btn btn-primary">登出</button>
                </form>
              </div>
            </div>
            <div class="card mb-3">
              <div class="card-body">
                <h2 class="mb-3 fs-5 card-title">WebAuthn</h2>
                <form onsubmit="registerWebAuthn(event)">
                  <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
                  <button type="submit" class="btn btn-primary">註冊</button>
                </form>
              </div>
            </div>
          <?php } ?>
        </div>
      <div class="col-md-4"></div>
    </div>
  </div>
</main>
<script src="/static/js/registerWebAuthn.js"></script>
<?= $this->partial('common/footer') ?>
