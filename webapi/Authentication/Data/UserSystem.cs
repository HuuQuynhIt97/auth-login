using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Data
{
    public class UserSystem
    {
        public UserSystem()
        {
            this.DateTime = DateTime.UtcNow;
        }
        [Key]
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        public int ID { get; set; }
        public int UserID { get; set; }
        public int SystemID { get; set; }
        [ForeignKey("SystemID")]
        public SystemCode SystemCode { get; set; }
        [ForeignKey("UserID")]
        public User User { get; set; }
        public bool Status { get; set; }
        public DateTime DateTime { get; set; }
    }
}
