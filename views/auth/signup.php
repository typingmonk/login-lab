<?= $this->partial('common/header') ?>
<main>
  <div class="container" style="max-width: 1120px;">
    <div class="row pt-5 pb-4">
      <div class="col-md-4"></div>
      <div class="col-md-4">
        <h1 class="mb-3 fs-2 fw-normal text-center">Sign Up</h1>
        <form method="post" action="/auth/signupPost">
          <div class="mb-3">
            <label for="username" class="form-label">使用者名稱</label>
            <input id="username" name="username" type="text" class="form-control">
          </div>
          <div class="mb-3">
            <label for="password" class="form-label">密碼</label>
            <input id="password" name="password" type="password" class="form-control">
          </div>
          <div class="mb-3">
            <label for="password_confirm" class="form-label">確認密碼</label>
            <input id="password_confirm" name="password_confirm" type="password" class="form-control">
          </div>
          <div class="mb-3">
            <label for="displayname" class="form-label">顯示暱稱</label>
            <input id="displayname" name="displayname" type="text" class="form-control">
          </div>
          <input type="hidden" name="csrf_token" value="<?= $this->escape($this->csrf_token) ?>">
          <div class="text-center">
            <button type="submit" class="btn btn-primary">Submit</button>
          </div>
        </form>
      </div>
      <div class="col-md-4"></div>
    </div>
  </div>
</main>
<?= $this->partial('common/footer') ?>
