-- MySQL dump 10.19
-- Host: localhost    Database: asterisk
CREATE TABLE `sip` (
  `id` varchar(20) NOT NULL DEFAULT '-1',
  `keyword` varchar(30) NOT NULL DEFAULT '',
  `data` text NOT NULL,
  `flags` int(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`,`keyword`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO `sip` VALUES ('1001','secret','LEAKsqlsecret',0),('1001','context','from-internal',0),('1001','md5secret','LEAKsqlmd5',0),('1001','callerid','John Smith <1001>',0),('1001','dial','PJSIP/1001',0);
CREATE TABLE `ampusers` (`username` varchar(255), `password_sha1` varchar(255), `extension_low` varchar(20), PRIMARY KEY (`username`)) ENGINE=InnoDB;
INSERT INTO `ampusers` VALUES ('admin','LEAKsha1admin',''),('operator','LEAKsha1operator','100');
INSERT INTO `ampusers` (`username`, `password_sha1`) VALUES ('readonly', 'LEAKexplicitcolumns');
-- PostgreSQL style block (FreeRADIUS radcheck)
COPY public.radcheck (id, username, attribute, op, value) FROM stdin;
1	bob	Cleartext-Password	:=	LEAKcopyvalue
2	bob	Expiration	:=	never
\.
-- MariaDB style: one row per line after VALUES
LOCK TABLES `sip` WRITE;
INSERT INTO `sip` VALUES
('1002','secret','LEAKmultiline1',52),
('1002','context','from-internal',13),
('1002','md5secret','LEAKmultiline2',52);
UNLOCK TABLES;
CREATE TABLE `users` (`extension` varchar(20), `password` varchar(20), `name` varchar(50), `voicemail` varchar(50));
INSERT INTO `users` VALUES ('1001','','John Smith','default'),('1002','','Jane Doe','novm');
