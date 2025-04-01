<?php
$auth_method = $this->auth_method;
?>
<?= $this->partial('common/header') ?>
<main>
  <div class="container" style="max-width: 1120px;">
    <div class="row pt-5 pb-4">
      <div class="col-md-4"></div>
        <div class="col-md-4">
          <?php if ($auth_method == 'password') { ?>
            <h1 class="mb-3 fs-2 fw-normal text-center">Login with password</h1>
            <form method="post" action="/auth/passwordLogin">
              <div class="mb-3">
                <label for="password" class="form-label">密碼</label>
                <input id="password" name="password" type="password" class="form-control">
              </div>
              <input type="hidden" name="username" value="<?= $this->escape($this->username) ?>">
              <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
              <div class="text-center">
                <button type="submit" class="btn btn-primary">Submit</button>
              </div>
            </form>
          <?php } ?>
          <?php if ($auth_method == 'web_authn') { ?>
            <h1 class="mb-3 fs-2 fw-normal text-center">Login with WebAuthn</h1>
            <form onsubmit="requestWebAuthn(event)">
              <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
              <div class="text-center">
                <button type="submit" class="btn btn-primary">Next</button>
              </div>
            </form>
          <?php } ?>
          <hr>
          <?php if ($auth_method != 'password') { ?>
            <form class="pt-1" method="post" action="/auth?type=password">
              <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
              <input type="hidden" name="username" value="<?= $this->escape($this->username) ?>">
              <div class="text-center">
                <button type="submit" class="w-75 btn btn-secondary">改用密碼登入</button>
              </div>
            </form>
          <?php } ?>
          <?php if ($auth_method != 'web_authn') { ?>
            <form class="pt-1" method="post" action="/auth?type=web_authn">
              <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
              <input type="hidden" name="username" value="<?= $this->escape($this->username) ?>">
              <div class="text-center">
                <button type="submit" class="w-75 btn btn-secondary">改用 WebAuthn 登入</button>
              </div>
            </form>
          <?php } ?>
        </div>
      <div class="col-md-4"></div>
    </div>
  </div>
</main>
<?php if ($auth_method == 'web_authn') { ?>
<script src="/static/js/helper.js"></script>
<script src="/static/js/requestWebAuthn.js"></script>
<?php } ?>
<?= $this->partial('common/footer') ?>
