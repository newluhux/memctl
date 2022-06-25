;; 用于实验危险的程序

(use-modules (gnu))
(use-service-modules base)

(operating-system
 (host-name "tester")
 (timezone "UTC")
 (locale "en_US.utf8")

 (bootloader (bootloader-configuration
              (bootloader grub-bootloader)
              (targets '("/dev/vda"))))
 (file-systems (cons (file-system
                      (device (file-system-label "tester"))
                      (mount-point "/")
                      (type "ext4"))
                     %base-file-systems))

 (users (cons (user-account
               (name "test")
               (comment "Tester")
               (group "users"))
              %base-user-accounts))

 (packages
  (append
   (map
    specification->package
    (list
     "screen" "tmux" "gdb" "strace" "gcc-toolchain"))
   %base-packages))

 (services %base-services))
