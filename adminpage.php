<?php 

if(isset($_POST['cwebco_updatekey']))
{
    if( wp_verify_nonce( $_POST['cwebcoupkeper_key_cstm_field'], 'cwebcoupkeper_key_cstm' ))
    {
        cwebco_upkepr_regenerate_key();
    }
}

$_upkepr_maintainance_validationkey = get_option('upkeprvalidationkeycstm' );
$upkepr_admin_page = admin_url( "admin.php?page=upkepr-Maintenance" );
?>
<link rel="stylesheet" href="<?php echo CWEB_UPKEPR_WS_PATH1; ?>css/style.css">
<script src="<?php echo CWEB_UPKEPR_WS_PATH1; ?>js/jquery.min.js"></script>
<div class="upkeprSettingMain">
    <div class="upkeprSettingBox">
        <div class="usMainTitle">Upkepr Setting</div>
        <div class="usMainSection">
            <div class="usmsLeft">
                <img src="<?php echo CWEB_UPKEPR_WS_PATH1; ?>img/site-logo.png" class="logoMain" alt="upkepr logo">
                <h3>Authentication Key</h3>
                <form action="<?php echo $upkepr_admin_page; ?>" method="post">
                    <div class="usmsInput">
                        <input type="text" id="upkepr_maintainance_validationkey" value="<?php if(isset($_upkepr_maintainance_validationkey)){echo esc_html($_upkepr_maintainance_validationkey);}?>">
                        <div class="usmsCopyIcon"><img src="<?php echo CWEB_UPKEPR_WS_PATH1; ?>img/copy.png" alt="upkepr" onclick="cwebco_copykey()"></div>
                        <div class="cstm_messagebox">Key copied</div>
                        <span class="usmsHelpText">Copy the key & Use in upkepr</span>
                        
                    </div>
                    <div class="usmsFooter">
                        <a href="#popup1" class="usButton">Regenerate Key</a>
                    </div>
                    <div id="popup1" class="overlay">
                        <div class="popup">
                            <h2>IMPORTANT ALERT</h2>
                            <a class="close" href="#">&times;</a>
                            <div class="content">
                                Regenerating the key will render old key as invalid. If you have already used the old key in upkepr, you
                                have to update new key in Upkepr.
                            </div>
                            <?php wp_nonce_field( "cwebcoupkeper_key_cstm", "cwebcoupkeper_key_cstm_field" ); ?>
                            <input type="submit" name="cwebco_updatekey" class="usButton" value="Yes, I am aware Update the Key">
                            </a>
                        </div>
                    </div>


                    <div class="overlay .cstm_messagebox">
                        <div class="popup">
                            <h2>Key copied</h2>
                            <a class="close" href="#">&times;</a>
                        </div>
                    </div>



                </form>
            </div>
            <div class="usmsRight">
                <div class="usmsRightInner">
                    <div class="usInfoList">
                        <div class="usInfoBox">
                            <div class="usibTitle">What is authentication key</div>
                            <div class="usibContent">It is a secure key that connects

                                your website with upkepr platform.
                                <br><br>

                                The key is unique. Please don’t share
                                the key with anyone. It should only
                                be used in the Upkepr.
                            </div>
                        </div>
                        <div class="usInfoBox">
                            <div class="usibTitle">Regenerating the key</div>
                            <div class="usibContent">If you regenerate the key, the old
                                key become invalid and is no more
                                available. You must update the new
                                key in UpKepr to keep the
                                connection with upkepr alive.
                            </div>
                        </div>
                    </div>
                    <div class="usInfoLinks">
                        <a class="usilBlue" href="https://upkepr.com">https://upkepr.com</a>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>


<script type="text/javascript">
    if (!function_exists('cwebco_copykey')){
    function cwebco_copykey() {
        var copyText = document.getElementById("upkepr_maintainance_validationkey");
        copyText.select();
        copyText.setSelectionRange(0, 99999); /* For mobile devices */
        navigator.clipboard.writeText(copyText.value);
        //alert("Key Copied");
        jQuery(".cstm_messagebox").toggle();


        setTimeout(function() {
            jQuery(".cstm_messagebox").toggle();
          }, 2000);
    }
}
</script>