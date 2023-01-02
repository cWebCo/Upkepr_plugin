<?php
/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * Dashboard. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              http://example.com
 * @since             1.0.0
 * @package           Upkepr Maintenance
 *
 * @wordpress-plugin
 * Plugin Name:       Upkepr Maintenance
 * Description:       "Upkepr Maintenance" is a WordPress plugin that allows Upkepr applications to stay connected with the website.
 * Version:           1.0.0
 * Author:            WebGarh Solutions
 * Author URI:        https://webgarh.com/
 * Text Domain:       upkepr-maintenance
 * Domain Path:       /languages
 */


define('SECRET_KEY','upKeprSecret');  // secret key can be a random string  and keep in secret from anyone
define('ALGORITHM','SHA256');

/* Use Domain as the folder name */
$PluginTextDomain="upkepr-maintenance";


/* Register Hooks For Start And Deactivate */
register_activation_hook( __FILE__, 'cwebco_upkepr_on_activate_this_plugin' );
register_deactivation_hook( __FILE__, 'cwebco_upkepr_on_deactivate_this_plugin' );

/* Constant */
define('CWEB_UPKEPR_FS_PATH1', plugin_dir_path(__FILE__) );
define('CWEB_UPKEPR_WS_PATH1', plugin_dir_url(__FILE__) );


if (!function_exists('cwebco_upkepr_on_activate_this_plugin')){
function cwebco_upkepr_on_activate_this_plugin()
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()';
    $pass = array(); //remember to declare $pass as an array
    $alphaLength = strlen($alphabet) - 1; //put the length -1 in cache
    for ($i = 0; $i < 50; $i++) {
        $n = rand(0, $alphaLength);
        $pass[] = $alphabet[$n];
    }
    $finalkey = implode($pass); //turn the array into a string
    $key_already_exist = trim(get_option('upkeprvalidationkeycstm'));
    if(empty($key_already_exist))
    {
        update_option('upkeprvalidationkeycstm', $finalkey );
    }
    
}
}


if (!function_exists('cwebco_upkepr_regenerate_key')){
function cwebco_upkepr_regenerate_key()
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()';
    $pass = array(); //remember to declare $pass as an array
    $alphaLength = strlen($alphabet) - 1; //put the length -1 in cache
    for ($i = 0; $i < 50; $i++) {
        $n = rand(0, $alphaLength);
        $pass[] = $alphabet[$n];
    }
    $finalkey = implode($pass); //turn the array into a string
    update_option('upkeprvalidationkeycstm', $finalkey );
}
}



if (!function_exists('cwebco_upkepr_on_deactivate_this_plugin')){
function cwebco_upkepr_on_deactivate_this_plugin()
{
    // currently no action
}
}
/* Register Hooks For Start And Deactivate // */




/* for admin pages */
if (!function_exists('cwebcoupkepr_wp_admin_menu')){
function cwebcoupkepr_wp_admin_menu() {

    // Register the parent menu.
    $menu = add_menu_page(
        __( 'upkepr Maintenance', $PluginTextDomain)
        , __( 'upkepr Maintenance', $PluginTextDomain )
        , 'manage_options'
        , 'upkepr-Maintenance'
        , 'cwebco_upekeper_display_my_menu'
    );
}
}
add_action( 'admin_menu', 'cwebcoupkepr_wp_admin_menu' );


if (!function_exists('cwebco_upekeper_display_my_menu')){
function cwebco_upekeper_display_my_menu()
{
    global $PluginTextDomain;
    if (!current_user_can('read')) {
        wp_die(__('You do not have sufficient permissions to access this page.',$PluginTextDomain));
    } else {
        //include(CWEB_FS_PATH1 . 'admin/settings.php');
        cwebco_upekeper_adminsettingspage();
    }
}
}

if (!function_exists('cwebco_upekeper_adminsettingspage')){
function cwebco_upekeper_adminsettingspage()
{
    require plugin_dir_path( __FILE__ ) . 'adminpage.php';
}   
}



add_action('rest_api_init', function ()
{
    /* to check if key is valid */
    register_rest_route( 'upkepr-isKeyValid', 'key',array(
    'methods' => 'POST',
    'callback' => 'cwebco_upkepr_isKeyValid'
    ));

    /* to check if key, domain and username is valid */
    register_rest_route( 'upkepr-is_keydomainusername_valid', 'data',array(
    'methods' => 'POST',
    'callback' => 'cwebco_upkepr_isKeyDomainUsernameValid'
    )); 

    /* to get all wp information data */
    register_rest_route( 'upkepr-wpinfo', 'wpinfo',array(
    'methods' => 'POST',
    'callback' => 'cwebco_upkepr_wpinfo'
    ));  

    /* to generate a new token */
    register_rest_route( 'upkepr-gettoken', 'byusername',array(
    'methods' => 'POST',
    'callback' => 'cwebco_upkepr_getlogintoken'
    ));

    /* to get login url */
    register_rest_route( 'upkepr-getloginurl', 'byusername',array(
    'methods' => 'POST',
    'callback' => 'cwebco_upkepr_getloginurl'
    ));

    /* internal api (not for app) */
    register_rest_route( 'upkepr-redirectnow', 'byusername',array(
    'methods' => 'GET',
    'callback' => 'validate_token_and_allow_redirect'
    ));


});


if (!function_exists('cwebcoupkepr_getuserid_frm_username')){
function cwebcoupkepr_getuserid_frm_username($username)
{
    $username = sanitize_text_field($username);
    $user = get_user_by( 'email', $username );
    if ( ! $user ) {
        $user = get_user_by( 'login', $username );
    }

    if( $user ) 
    {
        $user_id = $user->ID;
        if ( (! $user_id ) || ($user_id == '0') || empty($user_id) ) {
            return false;
        }
        else
        {
            return $user_id;
        }
    }
    else
    {
        return false;
    }
}
}

if (!function_exists('cwebco_upkepr_getlogintoken')){
function cwebco_upkepr_getlogintoken()
{
    $plugins_updates_array = array();
    $auth_header = apache_request_headers();
    $validationkey = $auth_header['Upkeprvalidationkey'];
    $upkeprvalidationdomain = $auth_header['Upkeprvalidationdomain'];

    $validation_message = cwebco_upkepr_intrnl_func_verifyKeyDomainUsername();
    if( $validation_message === true ) // Key, Username and Domain Verified
    {
        $posted_datapost = json_decode( file_get_contents( 'php://input' ), true );
        $username = $posted_datapost['username'];
        $user_id = cwebcoupkepr_getuserid_frm_username($username);
        $headers = array('alg'=>'HS256','typ'=>'JWT');
        $payload = array('domain'=>$upkeprvalidationdomain,'validationkey'=>$validationkey, 'user_id'=>$user_id, 'exp'=>(time() + 30));


        $resttoken = cwebco_upkepr_generaterandomtoken($headers, $payload, SECRET_KEY, $user_id);

        $data = array('status'=>'1','resttoken'=>$resttoken, 'username'=>$username);
        return new WP_REST_Response( $data, 200 );


    }
    else
    {
        $data = array('status'=>'0', 'message'=>$validation_message);
        return new WP_REST_Response( $data, 200 );
    }
}
}

if (!function_exists('cwebco_upkepr_generaterandomtoken')){
function cwebco_upkepr_generaterandomtoken($headers, $payload, $secret = 'secret', $user_id)
{
    $headers_encoded = base64url_encode(json_encode($headers));
    
    $payload_encoded = base64url_encode(json_encode($payload));
    
    $signature = hash_hmac(ALGORITHM, "$headers_encoded.$payload_encoded", SECRET_KEY, true);
    $signature_encoded = base64url_encode($signature);
    
    $jwt = "$headers_encoded.$payload_encoded.$signature_encoded";
    update_user_meta($user_id, 'upkprtkn', $jwt);
    return $jwt;
}
}

if (!function_exists('get_bearer_token')){
function get_bearer_token() {
    $headers_data = get_authorization_header();
    $token_data = $headers_data['authorization'];
    
    // HEADER: Get the access token from the header
    if (!empty($token_data)) {
        if (preg_match('/Bearer\s(\S+)/', $token_data, $matches)) {
            return $matches[1];
        }
    }
    return null;
}
}

if (!function_exists('get_authorization_header')){
function get_authorization_header(){
    $headers = array();
    $authorization = null;
    $sent_validationkey = null;
    $sent_domainname = null;

    if (isset($_SERVER['Authorization'])) {
        $authorization = trim($_SERVER["Authorization"]);
        $sent_validationkey = trim($_SERVER["Upkeprvalidationkey"]);
        $sent_domainname = trim($_SERVER["Upkeprvalidationdomain"]);
    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
        $authorization      = trim($_SERVER["HTTP_AUTHORIZATION"]);
        $sent_validationkey = trim($_SERVER["HTTP_UPKEPRVALIDATIONKEY"]);
        $sent_domainname    = trim($_SERVER["HTTP_UPKEPRVALIDATIONDOMAIN"]);
    } else if (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        if (isset($requestHeaders['Authorization'])) {
            $authorization = trim($requestHeaders['Authorization']);
            $sent_validationkey = trim($requestHeaders["Upkeprvalidationkey"]);
            $sent_domainname    = trim($requestHeaders["Upkeprvalidationdomain"]);
        }
    }
    $headers = array('authorization'=>$authorization, 'sent_validationkey'=> $sent_validationkey, 'sent_domainname'=> $sent_domainname);
    return $headers;
}
}


if (!function_exists('validate_token_and_allow_redirect')){
function validate_token_and_allow_redirect()
{
    $token_from_GET = sanitize_text_field($_GET['tkn']);
    $user_id = sanitize_text_field($_GET['usrid']); 
    
    $is_jwt_valid = is_jwt_valid($token_from_GET);

    $token_from_db = get_user_meta($user_id,'upkprtkn',true);

    if( ($is_jwt_valid  === TRUE ) && ($token_from_GET == $token_from_db) && ( !empty($user_id) ) && ($user_id != '0')  ) 
    {
        // validate other parameters and redirect user
        $user = get_user_by( 'id', $user_id ); 
        clean_user_cache($user_id);
        wp_clear_auth_cookie();
        wp_set_current_user( $user_id, $user->user_login );
        wp_set_auth_cookie( $user_id, true, true );
        update_user_caches( $user );
        //do_action( 'wp_login', $user->data->user_login );
        $admin_url = get_admin_url();


        if (is_user_logged_in() && is_front_page()) {
            wp_redirect($admin_url); # Using wp_safe_redirect
            exit; 
        }
        else
        {
            wp_redirect( site_url() );
            exit;
        }



    }
    else 
    {
        if($token_from_GET != $token_from_db)
        {
            echo json_encode(array('error' => 'Token not mmatched'));
        }

        if( (!empty($user_id) ) && ($user_id != '0'))
        {
            echo json_encode(array('error' => 'UserId not matched'));
        }
    }

    exit;
}
}


if (!function_exists('is_jwt_valid')){
function is_jwt_valid($jwt, $secret = 'secret') {
    // split the jwt
    $tokenParts = explode('.', $jwt);

    $header = base64_decode($tokenParts[0]);
    $payload = base64_decode($tokenParts[1]);
    $signature_provided = $tokenParts[2];

    // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
    $expiration = json_decode($payload)->exp;
    $is_token_expired = ($expiration - time()) < 0;

    // build a signature based on the header and payload using the secret
    $base64_url_header = base64url_encode($header);
    $base64_url_payload = base64url_encode($payload);
    $signature = hash_hmac(ALGORITHM, $base64_url_header . "." . $base64_url_payload, SECRET_KEY, true);
    $base64_url_signature = base64url_encode($signature);

    // verify it matches the signature provided in the jwt
    $is_signature_valid = ($base64_url_signature === $signature_provided);
    
    if ($is_token_expired || !$is_signature_valid) {
        return FALSE;
    } else {
        return TRUE;
    }
}
}

if (!function_exists('base64url_encode')){
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
}


if (!function_exists('cwebco_upkepr_isKeyValid')){
function cwebco_upkepr_isKeyValid()
{
    $auth_header = apache_request_headers();
    $validationkey = $auth_header['Upkeprvalidationkey'];
    $upkeprvalidationdomain = $auth_header['Upkeprvalidationdomain'];

    if( cwebco_upkepr_verifydomain($upkeprvalidationdomain) == false)
    {
        $data = array('status'=>'0', 'message'=>'Domain not verified');
        return new WP_REST_Response( $data, 200 );
        exit;
    }


    $origin_validationKey = get_option('upkeprvalidationkeycstm', true );
    if($validationkey == $origin_validationKey)
    {
        $key_status = 'valid';
        $status = '1';
    }
    else
    {
        $key_status = 'Not valid';
        $status = '0';
    }

    $data = array('status'=>$status, 'message'=>'Plugins Installed and Activated', 'keystatus'=>$key_status);
    return new WP_REST_Response( $data, 200 );
}
}

if (!function_exists('cwebco_upkepr_isKeyDomainUsernameValid')){
function cwebco_upkepr_isKeyDomainUsernameValid()
{
    $validation_message = cwebco_upkepr_intrnl_func_verifyKeyDomainUsername();
    if( $validation_message === true )
    {
        $data = array('status'=>'1', 'message'=>'Key, Username and Domain Verified');
        return new WP_REST_Response( $data, 200 );
    }
    else
    {
        $data = array('status'=>'0', 'message'=>$validation_message);
        return new WP_REST_Response( $data, 200 );
    }

    
}
}

if (!function_exists('cwebco_upkepr_intrnl_func_verifyKeyDomainUsername')){
function cwebco_upkepr_intrnl_func_verifyKeyDomainUsername()
{

    $auth_header = apache_request_headers();
    $validationkey = $auth_header['Upkeprvalidationkey'];
    $upkeprvalidationdomain = $auth_header['Upkeprvalidationdomain'];

    if( cwebco_upkepr_verifydomain($upkeprvalidationdomain) == false)
    {
        return 'Domain not verified';
        exit;
    }


    $origin_validationKey = get_option('upkeprvalidationkeycstm', true );
    if($validationkey != $origin_validationKey)
    {
        return 'Key not verified.';
        exit;
    }



    $posted_datapost = json_decode( file_get_contents( 'php://input' ), true );
    $username = $posted_datapost['username'];
    

    if( cwebco_upkepr_isuserexist($username) == false )
    {
        return 'username not verified';
        exit;
    }

    return true;
}
}



if (!function_exists('cwebco_upkepr_wpinfo')){
function cwebco_upkepr_wpinfo()
{
    if ( !function_exists( 'get_core_updates' ) ) { 
        require_once ABSPATH . '/wp-admin/includes/update.php'; 
    }


    $plugins_updates_array = array();
    $auth_header = apache_request_headers();
    $validationkey = $auth_header['Upkeprvalidationkey'];
    $upkeprvalidationdomain = $auth_header['Upkeprvalidationdomain'];

    if( cwebco_upkepr_verifydomain($upkeprvalidationdomain) == false)
    {
        $data = array('status'=>'0', 'message'=>'Domain not verified');
        return new WP_REST_Response( $data, 200 );
        exit;
    }


    $origin_validationKey = get_option('upkeprvalidationkeycstm', true );
    if($validationkey == $origin_validationKey)
    {
        $key_status = 'valid';
        $status = '1';
        /* wp core check */

        $wp_core_currntversion = get_bloginfo( 'version' );
        $wp_core_updates_array = get_core_updates();
        if(isset($wp_core_updates_array[0]->version))
        {
            $wp_core_updates_version = $wp_core_updates_array[0]->version;
        }
        else
        {
            $wp_core_updates_version = "errors in fetching updates";
        }
        
        if($wp_core_currntversion == $wp_core_updates_version)
        {
            $need_wp_core_update = '0';
        }
        else
        {
            $need_wp_core_update = '1';
        }

        /* wp core check // */

        /* plugins upate check */
        $plugin_info = cwebco_upkepr_cstm_plugins_update_check();
        /* plugins upate check */

        /* plugins upate check */
        $themes_info = cwebco_upkepr_cstm_theme_update_check();
        /* plugins upate check */

        $server = cwebco_upkepr_cstm_get_server_details();


        $wordpress_info = array('old_version'=>$wp_core_currntversion, 'latest_virsion'=>$wp_core_updates_version);


        $data = array('status'=>'1', 'wordpress_info'=>$wordpress_info, 'plugin_info'=>$plugin_info, 'themes_info'=>$themes_info,'server'=>$server);
        return new WP_REST_Response( $data, 200 );

    }
    else
    {
        $data = array('status'=>'0', 'message'=>'Plugins Installed and Activated', 'keystatus'=>'Not valid');
        return new WP_REST_Response( $data, 200 );
    }

}
}




if (!function_exists('cwebco_upkepr_cstm_plugins_update_check')){
function cwebco_upkepr_cstm_plugins_update_check() {
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    if (!function_exists('get_site_transient')) {
        require_once ABSPATH . 'wp-admin/includes/option.php';
    }

    
    $updates = get_site_transient('update_plugins');


    $plugins = get_plugins();

    $the_list = array();
    $activated_plugins = array();
    $deactivated_plugins = array();
    $i = 1;

        foreach ($plugins as $name => $plugin) {

            $the_list["plugins"][$i]["id"] = $name;
            $the_list["plugins"][$i]["name"] = $plugin["Name"];
            $the_list["plugins"][$i]["current_version"] = $plugin["Version"];
            if (isset($updates->response[$name])) {
                $the_list["plugins"][$i]["update"] = "yes";
                $update_data = array(
                    'slug'          =>  $updates->response[$name]->slug,
                    'new_version'   =>  $updates->response[$name]->new_version,
                    'url'           =>  $plugin['PluginURI'],
                    'package'       =>  $updates->response[$name]->package,
                    'name'          =>  $plugin['Title']
                );

                $plugin['update'] = $update_data;
                $the_list["plugins"][$i]["new_version"] = $updates->response[$name]->new_version;
                $update_future[] = $plugin;
                $update_future[$name] = $plugin;

            } else {
                $the_list["plugins"][$i]["update"] = "no";
            }


            if(is_plugin_active( $name ))
            {
                $the_list["plugins"][$i]["active_status"] = 'activated';
                $activated_plugins[] = $name;
            }
            else
            {
                $the_list["plugins"][$i]["active_status"] = 'deactivated';
                $deactivated_plugins[] = $name;
            }


            $i++;
        }


    $plugin_info = array(
        'update_future' => $update_future,
        'plugins'       => $plugins,
        'update_plugin' => $update_future,
        'actived_plugin'=> $activated_plugins,
        'plugins_count' => count($plugins)
    );



    return $plugin_info;
}
}



if (!function_exists('cwebco_upkepr_cstm_theme_update_check')){
function cwebco_upkepr_cstm_theme_update_check()
{

    if (!function_exists('get_themes')) {
        require_once ABSPATH . 'wp-admin/includes/theme.php';
    }
    if (!function_exists('get_site_transient')) {
        require_once ABSPATH . 'wp-admin/includes/option.php';
    }
    $activated_theme = get_current_theme();
    $updates = get_site_transient('update_themes');

    $themes = wp_get_themes();

    $the_list = array();
    $total_activated_themes = array();
    $total_deactivated_themes = array();
    $i = 1;

        $the_list["checked_revision"] = date("Y-m-d g:i A", intval($updates->last_checked));
        foreach ($themes as $name => $theme) {
            $theme_url = $theme->get( 'ThemeURI' ); 
            $old_version = $theme["Version"];
            $latest_verison = $updates->response[$name]['new_version'];
            $url = $updates->response[$name]['url'];
            $TextDomain = $theme["TextDomain"];
            $Description = $theme["Description"];
            $ThemeName = $theme["Name"];
            $tags = $theme->get('Tags');
            $screen = $theme->get_screenshot();
            $Author = $theme["Author"];
            
            $the_list["themes"][$i]["id"] = $name;
            $the_list["themes"][$i]["name"] = $theme["Name"];
            $the_list["themes"][$i]["current_version"] = $theme["Version"];

            if (isset($updates->response[$name])) {
                $the_list["themes"][$i]["update"] = "yes";
                $the_list["themes"][$i]["new_version"] = $updates->response[$name]['new_version'];
                $update_data = $updates->response[$name];
                $update_data['extra'] = 'data';
                $update_data['changelog_url'] = $url;
                $update_data['licence'] = 'dev';
                $update_data['credentials'] = false;
                $update_data['ssl'] = false;

                $update_future[] = $update_data;
                
            }
            else 
            {
                $the_list["themes"][$i]["update"] = "no";
            }


            if($activated_theme == $theme["Name"])
            {

                $total_activated_themes[] = $name;
                $status = 'Active';
            }
            else
            {
                $the_list["themes"][$i]["active_status"] = 'deactivated';
                $total_deactivated_themes[] = $name;
                $status = 'Deactivated';
            }

            $theme_details[] = array(
                'old_version'=>$old_version, 
                'latest_verison'=>$latest_verison, 
                'themeuri' => $theme_url,
                'url'=>$url,
                'status'=>$status,
                'screen'=>$screen,
                'theme_name'=>$ThemeName ,
                'description'=>$Description,
                'tags' => $tags,
                'Author' => $Author
            );

            $i++;
        }


    $themes_info = array(
            'update_future' => $update_future,
            'info'       => $theme_details,
            'themes_count' => count($themes)
        );


    return $themes_info;
}
}

if (!function_exists('cwebco_upkepr_cstm_get_server_details')){
function cwebco_upkepr_cstm_get_server_details()
{
    $server_details = array(
            'phpversion'    => phpversion(),
            'HEADER'        => $_SERVER,
            'usage_memory'  => memory_get_usage( $real_usage = false),
            'usage_memory_details'  => 'Returns the amount of memory, in bytes, that is currently being allocated to your PHP script.',
            'mysql_version' => mysqli_get_client_info()
    );

    return $server_details;
}
}

if (!function_exists('cwebco_upkepr_getloginurl')){
function cwebco_upkepr_getloginurl()
{
    $token = get_bearer_token();

    $is_jwt_valid = is_jwt_valid($token);
    if(! $is_jwt_valid)
    {
        $data = array('status'=>'0', 'message'=>'Token not validated');
        return new WP_REST_Response( $data, 200 );
        exit;
    }


    $validation_message = cwebco_upkepr_intrnl_func_verifyKeyDomainUsername();
    
    if( $validation_message === true ) // Key, Username and Domain Verified
    {
        $key_status = 'valid';
        $status = '1';
        $posted_datapost = json_decode( file_get_contents( 'php://input' ), true );
        $username = $posted_datapost['username'];

        if ( ! $user ) 
        {
            $user = get_user_by( 'email', $username );
        }
        if ( ! $user ) {
            $user = get_user_by( 'login', $username );
        }


        if ( !is_user_logged_in() ) 
        {
            if( $user ) 
            {
                $user_id = $user->ID;

                if ( (! $user_id) || ($user_id == '0') || empty($user_id) ) {
                    $data = array('status'=>'0', 'message'=>'Wrong Username');
                    return new WP_REST_Response( $data, 200 );
                    exit;
                }


                $autologin_url = generate_login_url_with_token_userid($token, $user_id);

                $data = array('status'=>'1', 'autologin_url'=>$autologin_url);
                return new WP_REST_Response( $data, 200 );
                exit;

                

            }
            else
            {
                $data = array('status'=>'0', 'message'=>'Can not find this user');
                return new WP_REST_Response( $data, 200 );
                exit;
            }

        }
        else
        {
            $data = array('status'=>'0', 'message'=>'User Already logged in');
            return new WP_REST_Response( $data, 200 );
            exit;
        }



    }
    else
    {
        $data = array('status'=>'0', 'message'=>$validation_message);
        return new WP_REST_Response( $data, 200 );
        exit;
    }
}
}


if (!function_exists('generate_login_url_with_token_userid')){
function generate_login_url_with_token_userid($token, $user_id)
{

    $url = site_url().'/wp-json/upkepr-redirectnow/byusername/?usrid='.$user_id.'&tkn='.$token;
    return $url;

}
}

if (!function_exists('cwebco_upkepr_verifydomain')){
function cwebco_upkepr_verifydomain($remote_domain)
{
    $remote_domain = trim($remote_domain);
    $remote_domain = str_replace('\\', '', $remote_domain);
    $remote_domain = stripslashes($remote_domain);
    $remote_domain = ltrim($remote_domain,"http://");
    $remote_domain = ltrim($remote_domain,"https://");
    $remote_domain = ltrim($remote_domain,"www");
    $remote_domain = rtrim($remote_domain,"/");

    $this_blog_url = site_url();
    $this_blog_url = trim($this_blog_url);
    $this_blog_url = str_replace('\\', '', $this_blog_url);
    $this_blog_url = stripslashes($this_blog_url);
    
    $this_blog_url = ltrim($this_blog_url,"http://");
    $this_blog_url = ltrim($this_blog_url,"https://");
    $this_blog_url = ltrim($this_blog_url,"www");
    $this_blog_url = rtrim($this_blog_url,"/");

    if( $remote_domain == $this_blog_url )
    {
        return true;
    }
    else
    {
        return false;
    }
}
}


if (!function_exists('cwebco_upkepr_isuserexist')){
function cwebco_upkepr_isuserexist($username)
{
    $username = sanitize_text_field($username);
    $user = get_user_by( 'email', $username );

    if ( ! $user ) {
        $user = get_user_by( 'login', $username );
    }

    if( $user ) 
    {
        $user_id = $user->ID;
        if ( (! $user_id ) || ($user_id == '0') || empty($user_id) ) {
            return false;
        }
        else
        {
            return true;
        }
    }
    else
    {
        return false;
    }


    return false;
}
}
